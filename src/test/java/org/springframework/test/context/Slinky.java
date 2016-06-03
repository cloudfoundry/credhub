package org.springframework.test.context;

import org.springframework.context.ApplicationContext;

public class Slinky {
  public static ApplicationContext getApplicationContext(Class<?> testClass) {
    TestContextBootstrapper testContextBootstrapper = BootstrapUtils.resolveTestContextBootstrapper(BootstrapUtils.createBootstrapContext(testClass));
    TestContext context = testContextBootstrapper.buildTestContext();
    return context.getApplicationContext();
  }

  public static void prepareTestInstance(Class<?> testClass, Object instance) {
    try {
      new TestContextManager(testClass).prepareTestInstance(instance);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
