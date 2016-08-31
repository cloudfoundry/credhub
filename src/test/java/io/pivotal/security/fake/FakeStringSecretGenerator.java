package io.pivotal.security.fake;

import io.pivotal.security.controller.v1.StringSecretParameters;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.StringSecret;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;


@Component
@Primary
@Profile("FakeStringSecretGenerator")
public class FakeStringSecretGenerator implements SecretGenerator<StringSecretParameters, StringSecret> {
  @Override
  public StringSecret generateSecret(StringSecretParameters parameters) {
    return new StringSecret(parameters.getType(), "generated string secret");
  }
}
