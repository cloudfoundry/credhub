package io.pivotal.security.helper;

import com.greghaskins.spectrum.Spectrum;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.TestContextManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static org.junit.Assert.fail;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;

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

  public static void wireAndUnwire(Object testInstance) {
    final MyTestContextManager testContextManager = new MyTestContextManager(testInstance.getClass());
    beforeEach(injectMocksAndBeans(testInstance, testContextManager));
    afterEach(cleanInjectedBeans(testInstance, testContextManager));
  }

  public static void autoTransactional(Object testInstance) {
    final MyTestContextManager testContextManager = new MyTestContextManager(testInstance.getClass());
    final PlatformTransactionManager transactionManager = testContextManager.getApplicationContext().getBean(PlatformTransactionManager.class);
    final AtomicReference<TransactionStatus> transaction = new AtomicReference<>();

    beforeEach(() -> transaction.set(transactionManager.getTransaction(new DefaultTransactionDefinition())));

    afterEach(() -> transactionManager.rollback(transaction.get()));
  }

  private static Spectrum.Block injectMocksAndBeans(Object testInstance, MyTestContextManager testContextManager) {
    return () -> {
      testContextManager.prepareTestInstance(testInstance);
      injectMocks(testInstance).run();
    };
  }

  private static Spectrum.Block cleanInjectedBeans(Object testInstance, MyTestContextManager testContextManager) {
    return () -> {
      Class klazz = testInstance.getClass();
      for (Field field : klazz.getDeclaredFields()) {
        for (Annotation annotation : field.getAnnotations()) {
          if (annotation.annotationType().getSimpleName().equals(InjectMocks.class.getSimpleName())) {
            field.setAccessible(true);
            testContextManager.autowireBean(field.get(testInstance));
          }
        }
      }
    };
  }

  public static Spectrum.Block injectMocks(Object testInstance) {
    return () -> MockitoAnnotations.initMocks(testInstance);
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
}
