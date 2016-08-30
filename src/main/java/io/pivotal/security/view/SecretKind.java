package io.pivotal.security.view;

import java.util.function.Function;

public enum SecretKind implements SecretKindFromString {
  VALUE {
    @Override
    public <T, R> Function<T, R> map(Map<T, R> map) {
      return map::value;
    }

    @Override
    public <T> T selectFrom(Enumeration<T> enumeration) {
      return enumeration.value();
    }
  },
  PASSWORD {
    @Override
    public <T, R> Function<T, R> map(Map<T, R> map) {
      return map::password;
    }

    @Override
    public <T> T selectFrom(Enumeration<T> enumeration) {
      return enumeration.password();
    }
  },
  CERTIFICATE {
    @Override
    public <T, R> Function<T, R> map(Map<T, R> map) {
      return map::certificate;
    }

    @Override
    public <T> T selectFrom(Enumeration<T> enumeration) {
      return enumeration.certificate();
    }
  };

  public abstract <T, R> Function<T, R> map(Map<T, R> map);

  public abstract <T> T selectFrom(Enumeration<T> enumeration);

  public interface Enumeration<T> {
    T value();
    T password();
    T certificate();
  }

  public interface Map<T, R> {
    R value(T t);
    R password(T t);
    R certificate(T t);
  }

  public static class IdentityMap<T> implements Map<T, T> {

    @Override
    public T value(T t) {
      return t;
    }

    @Override
    public T password(T t) {
      return t;
    }

    @Override
    public T certificate(T t) {
      return t;
    }
  }

  public static class NullMap<T, R> implements Map<T, R> {

    @Override
    public R value(T t) {
      return null;
    }

    @Override
    public R password(T t) {
      return null;
    }

    @Override
    public R certificate(T t) {
      return null;
    }
  }
}
