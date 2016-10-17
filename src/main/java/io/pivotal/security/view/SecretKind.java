package io.pivotal.security.view;

import io.pivotal.security.util.CheckedFunction;

import java.util.Objects;
import java.util.function.Function;

public enum SecretKind implements SecretKindFromString {
  VALUE {
    @Override
    public <T, R> Function<T, R> lift(Mapping<T, R> mapping) {
      Objects.requireNonNull(mapping);
      return (t) -> mapping.value(this, t);
    }

    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.value(this, t);
    }
  },
  PASSWORD {
    @Override
    public <T, R> Function<T, R> lift(Mapping<T, R> mapping) {
      Objects.requireNonNull(mapping);
      return (t) -> mapping.password(this, t);
    }

    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.password(this, t);
    }
  },
  CERTIFICATE {
    @Override
    public <T, R> Function<T, R> lift(Mapping<T, R> mapping) {
      Objects.requireNonNull(mapping);
      return (t) -> mapping.certificate(this, t);
    }

    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.certificate(this, t);
    }
  },
  SSH {
    @Override
    public <T, R> Function<T, R> lift(Mapping<T, R> mapping) {
      Objects.requireNonNull(mapping);
      return (t) -> mapping.ssh(this, t);
    }

    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.ssh(this, t);
    }
  },
  RSA {
    @Override
    public <T, R> Function<T, R> lift(Mapping<T, R> mapping) {
      Objects.requireNonNull(mapping);
      return (t) -> mapping.rsa(this, t);
    }

    @Override
    public <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping) {
      Objects.requireNonNull(mapping);
      return t -> mapping.rsa(this, t);
    }
  };

  public abstract <T, R> Function<T, R> lift(Mapping<T, R> mapping);

  public abstract <T, R, E extends Throwable> CheckedFunction<T, R, E> lift(CheckedMapping<T, R, E> mapping);

  public interface Mapping<T, R> {
    R value(SecretKind secretKind, T t);
    R password(SecretKind secretKind, T t);
    R certificate(SecretKind secretKind, T t);
    R ssh(SecretKind secretKind, T t);
    R rsa(SecretKind secretKind, T t);

    default <V> Mapping<V, R> compose(Mapping<? super V, ? extends T> before) {
      Objects.requireNonNull(before);
      return new Mapping<V, R>() {
        @Override
        public R value(SecretKind secretKind, V v) {
          return Mapping.this.value(secretKind, before.value(secretKind, v));
        }

        @Override
        public R password(SecretKind secretKind, V v) {
          return Mapping.this.password(secretKind, before.password(secretKind, v));
        }

        @Override
        public R certificate(SecretKind secretKind, V v) {
          return Mapping.this.certificate(secretKind, before.certificate(secretKind, v));
        }

        @Override
        public R ssh(SecretKind secretKind, V v) {
          return Mapping.this.ssh(secretKind, before.ssh(secretKind, v));
        }

        @Override
        public R rsa(SecretKind secretKind, V v) {
          return Mapping.this.rsa(secretKind, before.rsa(secretKind, v));
        }
      };
    }
  }

  public interface CheckedMapping<T, R, E extends Throwable> {
    R value(SecretKind secretKind, T t) throws E;
    R password(SecretKind secretKind, T t) throws E;
    R certificate(SecretKind secretKind, T t) throws E;
    R ssh(SecretKind secretKind, T t) throws E;
    R rsa(SecretKind secretKind, T t) throws E;

    default <V> CheckedMapping<V, R, E> compose(Mapping<? super V, ? extends T> before) {
      Objects.requireNonNull(before);
      return new CheckedMapping<V, R, E>() {
        @Override
        public R value(SecretKind secretKind, V v) throws E {
          return CheckedMapping.this.value(secretKind, before.value(secretKind, v));
        }

        @Override
        public R password(SecretKind secretKind, V v) throws E {
          return CheckedMapping.this.password(secretKind, before.password(secretKind, v));
        }

        @Override
        public R certificate(SecretKind secretKind, V v) throws E {
          return CheckedMapping.this.certificate(secretKind, before.certificate(secretKind, v));
        }

        @Override
        public R ssh(SecretKind secretKind, V v) throws E {
          return CheckedMapping.this.ssh(secretKind, before.ssh(secretKind, v));
        }

        @Override
        public R rsa(SecretKind secretKind, V v) throws E {
          return CheckedMapping.this.rsa(secretKind, before.rsa(secretKind, v));
        }
      };
    }
  }
}
