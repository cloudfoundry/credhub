package org.cloudfoundry.credhub.util;

@FunctionalInterface
public interface CheckedConsumer<T, E extends Throwable> {

  void accept(T t) throws E;
}
