package com.greghaskins.spectrum;

import org.springframework.test.context.TestContextManager;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class SpringConstructorBlock implements Spectrum.Block {

  private final Class<?> klass;
  private final TestContextManager testContextManager;

  public SpringConstructorBlock(Class<?> klass) {
    this.klass = klass;
    testContextManager = new TestContextManager(this.klass);
  }

  @Override
  public void run() throws Throwable {
    try {
      final Constructor<?> constructor = klass.getDeclaredConstructor();
      constructor.setAccessible(true);
      testContextManager.prepareTestInstance(constructor.newInstance());
    } catch (final InvocationTargetException e) {
      throw e.getTargetException();
    } catch (final Exception e) {
      throw new UnableToConstructSpecException(klass, e);
    }
  }
}
