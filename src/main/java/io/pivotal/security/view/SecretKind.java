package io.pivotal.security.view;

import io.pivotal.security.util.CheckedFunction;

import java.util.Objects;

public enum SecretKind implements SecretKindFromString {
  VALUE {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.value(this, t);
    }
  },
  PASSWORD {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.password(this, t);
    }
  },
  CERTIFICATE {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.certificate(this, t);
    }
  },
  SSH {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.ssh(this, t);
    }
  },
  RSA {
    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.rsa(this, t);
    }
  };

  public abstract <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping);

  public interface CheckedMapping<T, R, E extends Throwable> {
    R value(SecretKind secretKind, T t) throws E;
    R password(SecretKind secretKind, T t) throws E;
    R certificate(SecretKind secretKind, T t) throws E;
    R ssh(SecretKind secretKind, T t) throws E;
    R rsa(SecretKind secretKind, T t) throws E;
  }
}
