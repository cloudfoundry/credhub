package io.pivotal.security.helper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Suppliers;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.JpaAuditingHandler;
import io.pivotal.security.util.CurrentTimeProvider;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.flywaydb.core.Flyway;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationContext;
import org.springframework.data.repository.CrudRepository;
import org.springframework.test.context.TestContextManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.Calendar;
import java.util.Objects;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;


public class SpectrumHelper {
  public static <T extends Throwable> void itThrows(final String behavior, final Class<T> throwableClass, final Spectrum.Block block) {
    Spectrum.it(behavior, () -> {
      try {
        block.run();
        fail("Expected " + throwableClass.getSimpleName() + " to be thrown, but it wasn't");
      } catch (Throwable t) {
        if (!throwableClass.equals(t.getClass())) {
          fail("Expected " + throwableClass.getSimpleName() + " to be thrown, but got " + t.getClass().getSimpleName());
        }
      }
    });
  }

  public static <T extends Throwable> void itThrowsWithMessage(final String behavior, final Class<T> throwableClass, final String message, final Spectrum.Block block) {
    Spectrum.it(behavior, () -> {
      try {
        block.run();
        fail("Expected " + throwableClass.getSimpleName() + " to be thrown, but it wasn't");
      } catch (Throwable t) {
        if (!(throwableClass.equals(t.getClass()) && Objects.equals(message, t.getMessage()))) {
          fail("Expected " + throwableClass.getSimpleName() + " with message " + message +
              " to be thrown, but got " + t.getClass().getSimpleName() + " with message " + t.getMessage());
        }
      }
    });
  }

  public static void cleanUpBeforeTests(final Object testInstance) {
    Supplier<MyTestContextManager> myTestContextManagerSupplier = getTestContextManagerSupplier(testInstance);
    beforeEach(() -> {
      Flyway flyway = myTestContextManagerSupplier.get().getApplicationContext().getBean(Flyway.class);
      flyway.clean();
      flyway.migrate();
    });
  }

  public static void cleanUpAfterTests(final Object testInstance) {
    Supplier<MyTestContextManager> myTestContextManagerSupplier = getTestContextManagerSupplier(testInstance);
    afterEach(() -> {
      Flyway flyway = myTestContextManagerSupplier.get().getApplicationContext().getBean(Flyway.class);
      flyway.clean();
      flyway.migrate();
    });
  }

  public static void wireAndUnwire(final Object testInstance) {
    Supplier<MyTestContextManager> myTestContextManagerSupplier = getTestContextManagerSupplier(testInstance);
    beforeEach(injectMocksAndBeans(testInstance, myTestContextManagerSupplier));
    afterEach(cleanInjectedBeans(testInstance, myTestContextManagerSupplier));
    afterEach(() -> {
      DataSource dataSource = myTestContextManagerSupplier.get().getApplicationContext().getBean(DataSource.class);
      dataSource.purge();
    });
  }

  public static Supplier<MyTestContextManager> getTestContextManagerSupplier(Object testInstance) {
    return Suppliers.memoize(() -> new MyTestContextManager(testInstance.getClass()))::get;
  }

  public static String json(Object o) throws IOException {
    return new ObjectMapper().writeValueAsString(o);
  }

  // Don't use this without talking to Rick
  public static void autoTransactional(final Object testInstance) {
    final Supplier<PlatformTransactionManager> transactionManagerSupplier = Suppliers.memoize(() -> {
      final MyTestContextManager testContextManager = new MyTestContextManager(testInstance.getClass());
      return testContextManager.getApplicationContext().getBean(PlatformTransactionManager.class);
    })::get;

    final AtomicReference<TransactionStatus> transaction = new AtomicReference<>();

    beforeEach(() -> transaction.set(transactionManagerSupplier.get().getTransaction(new DefaultTransactionDefinition())));

    afterEach(() -> transactionManagerSupplier.get().rollback(transaction.get()));
  }

  public static Consumer<Long> mockOutCurrentTimeProvider(Object testInstance) {
    final Supplier<MyTestContextManager> testContextManagerSupplier = Suppliers.memoize(() -> new MyTestContextManager(testInstance.getClass()))::get;
    final CurrentTimeProvider mockCurrentTimeProvider = mock(CurrentTimeProvider.class);

    beforeEach(() -> {
      final JpaAuditingHandler auditingHandler = testContextManagerSupplier.get().getApplicationContext().getBean(JpaAuditingHandler.class);
      auditingHandler.setDateTimeProvider(mockCurrentTimeProvider);
    });

    afterEach(() -> {
      final ApplicationContext applicationContext = testContextManagerSupplier.get().getApplicationContext();
      final CurrentTimeProvider realCurrentTimeProvider = applicationContext.getBean(CurrentTimeProvider.class);
      final JpaAuditingHandler auditingHandler = applicationContext.getBean(JpaAuditingHandler.class);
      auditingHandler.setDateTimeProvider(realCurrentTimeProvider);
    });

    return (epochMillis) -> { when(mockCurrentTimeProvider.getNow()).thenReturn(getNow(epochMillis)); };
  }

  private static Spectrum.Block injectMocksAndBeans(Object testInstance, Supplier<MyTestContextManager> testContextManager) {
    return () -> {
      testContextManager.get().prepareTestInstance(testInstance);
      injectMocks(testInstance).run();
    };
  }

  private static Spectrum.Block cleanInjectedBeans(Object testInstance, Supplier<MyTestContextManager> testContextManager) {
    return () -> {
      Class klazz = testInstance.getClass();
      for (Field field : klazz.getDeclaredFields()) {
        for (Annotation annotation : field.getAnnotations()) {
          if (annotation.annotationType().getSimpleName().equals(InjectMocks.class.getSimpleName())) {
            field.setAccessible(true);
            testContextManager.get().autowireBean(field.get(testInstance));
          }
        }
      }
    };
  }

  public static Spectrum.Block injectMocks(Object testInstance) {
    return () -> MockitoAnnotations.initMocks(testInstance);
  }

  public static CountMemo markRepository(CrudRepository crudRepository) {
    return new CountMemo(crudRepository).mark();
  }

  private static class MyTestContextManager extends TestContextManager {
    MyTestContextManager(Class<?> testClass) {
      super(testClass);
    }

    ApplicationContext getApplicationContext() {
      return getTestContext().getApplicationContext();
    }

    void autowireBean(Object existingBean) {
      getApplicationContext().getAutowireCapableBeanFactory().autowireBean(existingBean);
    }
  }

  private static Calendar getNow(long epochMillis) {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(epochMillis);
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
  }

}
