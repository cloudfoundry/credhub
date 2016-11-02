package io.pivotal.security.util;

@FunctionalInterface
public interface CheckedFunction<T, E extends Throwable> {
  T apply(T t) throws E;
}
