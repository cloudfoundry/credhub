package io.pivotal.security.controller.v1;

import io.pivotal.security.request.RsaGenerationParameters;
import org.springframework.stereotype.Component;

@Component
public class RsaSecretParametersFactory {

  public RsaGenerationParameters get() {
    return new RsaGenerationParameters();
  }
}
