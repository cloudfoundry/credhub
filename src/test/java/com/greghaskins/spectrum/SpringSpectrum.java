package com.greghaskins.spectrum;

import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunNotifier;

import java.util.ArrayDeque;
import java.util.Deque;

@SuppressWarnings("unused")
public class SpringSpectrum extends Runner {

  public static void describe(final String context, final Spectrum.Block block) {
    final Suite suite = getCurrentSuite().addSuite(context);
    beginDefinition(suite, block);
  }

  public static void fdescribe(final String context, final Spectrum.Block block) {
    final Suite suite = getCurrentSuite().addSuite(context);
    suite.focus();
    beginDefinition(suite, block);
  }

  public static void it(final String behavior, final Spectrum.Block block) {
    getCurrentSuite().addSpec(behavior, block);
  }

  public static void fit(final String behavior, final Spectrum.Block block) {
    getCurrentSuite().addSpec(behavior, block).focus();
  }

  public static void beforeEach(final Spectrum.Block block) {
    getCurrentSuite().beforeEach(block);
  }

  public static void afterEach(final Spectrum.Block block) {
    getCurrentSuite().afterEach(block);
  }

  public static void beforeAll(final Spectrum.Block block) {
    getCurrentSuite().beforeAll(block);
  }

  public static void afterAll(final Spectrum.Block block) {
    getCurrentSuite().afterAll(block);
  }

  private static final Deque<Suite> suiteStack = new ArrayDeque<>();

  private final Suite rootSuite;

  public SpringSpectrum(Class<?> testClass) {
    final Description description = Description.createSuiteDescription(testClass);
    this.rootSuite = Suite.rootSuite(description);
    beginDefinition(this.rootSuite, new SpringConstructorBlock(testClass));
  }

  @Override
  public Description getDescription() {
    return rootSuite.getDescription();
  }

  @Override
  public void run(RunNotifier notifier) {
    rootSuite.run(notifier);
  }

  synchronized private static void beginDefinition(final Suite suite, final Spectrum.Block definitionBlock) {
    suiteStack.push(suite);
    try {
      definitionBlock.run();
    } catch (final Throwable e) {
      it("encountered an error", new FailingBlock(e));
    }
    suiteStack.pop();
  }

  synchronized private static Suite getCurrentSuite() {
    return suiteStack.peek();
  }
}
