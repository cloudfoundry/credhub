package io.pivotal.security.model;

import java.util.function.Supplier;

public enum SecretType {
  value {
    @Override
    public <T> T enumerate(Supplier<T> ifValue, Supplier<T> ifCertificate) {
      return ifValue.get();
    }
  },
  certificate {
    @Override
    public <T> T enumerate(Supplier<T> ifValue, Supplier<T> ifCertificate) {
      return ifCertificate.get();
    }
  };

  public abstract <T> T enumerate(Supplier<T> ifValue, Supplier<T> ifCertificate);
}
