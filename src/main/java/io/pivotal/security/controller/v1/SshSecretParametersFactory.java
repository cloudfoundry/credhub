package io.pivotal.security.controller.v1;

import io.pivotal.security.request.SshGenerationParameters;
import org.springframework.stereotype.Component;

@Component
public class SshSecretParametersFactory {

  public SshGenerationParameters get() {
    return new SshGenerationParameters();
  }
}
