package io.pivotal.security.view;

import io.pivotal.security.util.CheckedFunction;

import java.util.Objects;

public enum SecretKind implements SecretKindFromString {
  VALUE {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::value;
    }
  },
  PASSWORD {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::password;
    }
  },
  CERTIFICATE {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::certificate;
    }
  },
  SSH {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::ssh;
    }
  },
  RSA {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::rsa;
    }
  };

  public abstract <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping);

  public interface CheckedMapping<T, R, E extends Throwable> {
    R value(T t) throws E;
    R password(T t) throws E;
    R certificate(T t) throws E;
    R ssh(T t) throws E;
    R rsa(T t) throws E;
  }
}
