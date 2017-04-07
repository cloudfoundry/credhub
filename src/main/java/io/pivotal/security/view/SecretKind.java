package io.pivotal.security.view;

import io.pivotal.security.util.CheckedFunction;
import java.util.Objects;

public enum SecretKind {
  VALUE {
    @Override
    public <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::value;
    }
  },
  JSON {
    @Override
    public <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::json;
    }
  },
  PASSWORD {
    @Override
    public <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping) {
      throw new RuntimeException("No longer trapped in the monad");
    }
  },
  CERTIFICATE {
    @Override
    public <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping) {
      Objects.requireNonNull(mapping);
      return mapping::certificate;
    }
  },
  SSH {
    @Override
    public <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping) {
      throw new RuntimeException("No longer trapped in the monad");
    }
  },
  RSA {
    @Override
    public <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping) {
      throw new RuntimeException("No longer trapped in the monad");
    }
  };

  public abstract <T, E extends Throwable> CheckedFunction<T, E> lift(CheckedMapping<T, E> mapping);

  public interface CheckedMapping<T, E extends Throwable> {

    T value(T t) throws E;

    T json(T t) throws E;

    T certificate(T t) throws E;
  }
}
