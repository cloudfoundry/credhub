package io.pivotal.security.helper;

import com.greghaskins.spectrum.Spectrum;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.fail;

public class SpectrumHelper {
  public static <T extends Throwable> void itThrows(final String behavior, final Class<T> throwableClass, final
  Spectrum.Block block) {
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

  public static Spectrum.Block injectBeans(Class configuration, Object testInstance) {
    return () -> {
      // 1. inject beans marked with @Autowired or @InjectMocks
      // 3. inject @InjectMocks
    };
  }

  public static Spectrum.Block cleanInjectedBeans() {
    return () -> {

    };
  }

  public static Spectrum.Block injectMocks(Object testInstance) {
    return () -> MockitoAnnotations.initMocks(testInstance);
  }
}
