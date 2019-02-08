package org.cloudfoundry.credhub.utils;

@FunctionalInterface
public interface ExceptionThrowingFunction<P, R, E extends Throwable> {
  R apply(P parameter) throws E;
}
