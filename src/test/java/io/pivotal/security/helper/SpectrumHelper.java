package io.pivotal.security.helper;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Suppliers;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestContextManager;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.security.Security;
import java.util.Calendar;
import java.util.Objects;
import java.util.TimeZone;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

public class SpectrumHelper {

  private static final String MOCK_BEAN_SIMPLE_NAME = MockBean.class.getSimpleName();
  private static final String SPY_BEAN_SIMPLE_NAME = SpyBean.class.getSimpleName();

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

  public static void wireAndUnwire(final Object testInstance) {
    Supplier<MyTestContextManager> myTestContextManagerSupplier = getTestContextManagerSupplier(testInstance);
    beforeEach(() -> {
      MyTestContextManager myTestContextManager = myTestContextManagerSupplier.get();
      myTestContextManager.prepareTestInstance(testInstance);

      cleanUpDatabase(myTestContextManagerSupplier);
    });

    afterEach(() -> {
      cleanMockBeans(testInstance);

      myTestContextManagerSupplier.get().getApplicationContext().getBean(DataSource.class).purge();
    });
  }

  private static void cleanUpDatabase(Supplier<MyTestContextManager> myTestContextManagerSupplier) {
    ApplicationContext applicationContext = myTestContextManagerSupplier.get().getApplicationContext();
    JdbcTemplate jdbcTemplate = applicationContext.getBean(JdbcTemplate.class);
    jdbcTemplate.execute("delete from secret_name");
    jdbcTemplate.execute("truncate table auth_failure_audit_record");
    jdbcTemplate.execute("truncate table operation_audit_record");
    jdbcTemplate.execute("delete from encryption_key_canary");

    EncryptionKeyCanaryMapper encryptionKeyCanaryMapper = applicationContext.getBean(EncryptionKeyCanaryMapper.class);
    encryptionKeyCanaryMapper.mapUuidsToKeys();
  }

  static Supplier<MyTestContextManager> getTestContextManagerSupplier(Object testInstance) {
    return Suppliers.memoize(() -> new MyTestContextManager(testInstance.getClass()))::get;
  }

  public static String json(Object o) throws IOException {
    return new ObjectMapper().writeValueAsString(o);
  }

  public static Consumer<Long> mockOutCurrentTimeProvider(CurrentTimeProvider mockCurrentTimeProvider) {
    return (epochMillis) -> { when(mockCurrentTimeProvider.getNow()).thenReturn(getNow(epochMillis)); };
  }

  private static Calendar getNow(long epochMillis) {
    Calendar.Builder builder = new Calendar.Builder();
    builder.setInstant(epochMillis);
    builder.setTimeZone(TimeZone.getTimeZone("UTC"));
    return builder.build();
  }

  private static void cleanMockBeans(Object testInstance) {
    Class klazz = testInstance.getClass();
    for (Field field : klazz.getDeclaredFields()) {
      for (Annotation annotation : field.getAnnotations()) {
        String simpleName = annotation.annotationType().getSimpleName();
        if (simpleName.equals(MOCK_BEAN_SIMPLE_NAME) || simpleName.equals(SPY_BEAN_SIMPLE_NAME)) {
          field.setAccessible(true);
          try {
            Mockito.reset(field.get(testInstance));
            field.set(testInstance, null);
          } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
          }
        }
      }
    }
  }

  public static Spectrum.Block injectMocks(Object testInstance) {
    return () -> MockitoAnnotations.initMocks(testInstance);
  }

  public static BouncyCastleProvider getBouncyCastleProvider() {
    BouncyCastleProvider bouncyCastleProvider = (BouncyCastleProvider) Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

    if (bouncyCastleProvider == null) {
      bouncyCastleProvider = new BouncyCastleProvider();
      Security.addProvider(bouncyCastleProvider);
    }

    return bouncyCastleProvider;
  }

  private static class MyTestContextManager extends TestContextManager {
    MyTestContextManager(Class<?> testClass) {
      super(testClass);
    }

    ApplicationContext getApplicationContext() {
      return getTestContext().getApplicationContext();
    }
  }
}
