package io.pivotal.security.controller.v1;

import org.springframework.stereotype.Component;

@Component
public class SshSecretParameters implements RequestParameters {
  @Override
  public String getType() {
    throw new UnsupportedOperationException();
  }
}
