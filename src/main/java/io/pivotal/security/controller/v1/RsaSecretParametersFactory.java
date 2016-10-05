package io.pivotal.security.controller.v1;

import org.springframework.stereotype.Component;

@Component
public class RsaSecretParametersFactory {
  public RsaSecretParameters get() {
    return new RsaSecretParameters();
  }
}
