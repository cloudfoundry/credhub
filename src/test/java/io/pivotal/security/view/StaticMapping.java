package io.pivotal.security.view;

import java.util.NoSuchElementException;

public class StaticMapping<T, R> implements SecretKind.CheckedMapping<T, R, NoSuchElementException> {

  private final R value;
  private final R password;
  private final R certificate;
  private final R ssh;
  private final R rsa;

  public StaticMapping(R value, R password, R certificate, R ssh, R rsa) {
    this.value = value;
    this.password = password;
    this.certificate = certificate;
    this.ssh = ssh;
    this.rsa = rsa;
  }

  @Override
  public R value(SecretKind secretKind, T t) {
    return value;
  }

  @Override
  public R password(SecretKind secretKind, T t) {
    return password;
  }

  @Override
  public R certificate(SecretKind secretKind, T t) {
    return certificate;
  }

  @Override
  public R ssh(SecretKind secretKind, T t) {
    return ssh;
  }

  @Override
  public R rsa(SecretKind secretKind, T t) {
    return rsa;
  }
}
