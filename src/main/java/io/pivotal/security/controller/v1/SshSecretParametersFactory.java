package io.pivotal.security.controller.v1;

import org.springframework.stereotype.Component;

@Component
public class SshSecretParametersFactory {

  public SshSecretParameters get() {
    return new SshSecretParameters();
  }
}
