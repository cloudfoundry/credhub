package io.pivotal.security.util;

@FunctionalInterface
public interface CheckedFunction<T, R, E extends Throwable> {
  R apply(T t) throws E;
}