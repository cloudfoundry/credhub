package io.pivotal.security.helper;

import com.greghaskins.spectrum.Spectrum;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.test.context.TestContextManager;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static org.junit.Assert.fail;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;

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

    void autowireBean(Object existingBean) {
      getTestContext().getApplicationContext().getAutowireCapableBeanFactory().autowireBean(existingBean);
    }
  }
}
