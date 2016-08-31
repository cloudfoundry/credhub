package io.pivotal.security.view;

import java.util.function.Function;

public enum SecretKind implements SecretKindFromString {
  VALUE {
    @Override
    public <T, R> Function<T, R> map(Mapping<T, R> mapping) {
      return (t) -> mapping.value(this, t);
    }

  },
  PASSWORD {
    @Override
    public <T, R> Function<T, R> map(Mapping<T, R> mapping) {
      return (t) -> mapping.password(this, t);
    }

  },
  CERTIFICATE {
    @Override
    public <T, R> Function<T, R> map(Mapping<T, R> mapping) {
      return (t) -> mapping.certificate(this, t);
    }

  };

  public abstract <T, R> Function<T, R> map(Mapping<T, R> mapping);

  public interface Mapping<T, R> {
    R value(SecretKind secretKind, T t);
    R password(SecretKind secretKind, T t);
    R certificate(SecretKind secretKind, T t);
  }

  public static class IdentityMapping<T> implements Mapping<T, T> {

    @Override
    public T value(SecretKind secretKind, T t) {
      return t;
    }

    @Override
    public T password(SecretKind secretKind, T t) {
      return t;
    }

    @Override
    public T certificate(SecretKind secretKind, T t) {
      return t;
    }
  }

  public static class NullMapping<T, R> implements Mapping<T, R> {

    @Override
    public R value(SecretKind secretKind, T t) {
      return null;
    }

    @Override
    public R password(SecretKind secretKind, T t) {
      return null;
    }

    @Override
    public R certificate(SecretKind secretKind, T t) {
      return null;
    }
  }

  public static class StaticMapping<T> implements Mapping<Void, T> {

    private final T value;
    private final T password;
    private final T certificate;

    public StaticMapping(T value, T password, T certificate) {
      this.value = value;
      this.password = password;
      this.certificate = certificate;
    }

    @Override
    public T value(SecretKind secretKind, Void v) {
      return value;
    }

    @Override
    public T password(SecretKind secretKind, Void v) {
      return password;
    }

    @Override
    public T certificate(SecretKind secretKind, Void v) {
      return certificate;
    }
  }
}
