package org.cloudfoundry.credhub.utils;

@FunctionalInterface
public interface CheckedConsumer<T, E extends Throwable> {

  void accept(T t) throws E;
}
