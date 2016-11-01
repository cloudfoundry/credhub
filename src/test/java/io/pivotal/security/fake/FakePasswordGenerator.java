package io.pivotal.security.fake;

import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.StringSecret;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Component
@Primary
public class FakePasswordGenerator implements SecretGenerator<PasswordGenerationParameters, StringSecret> {
  final private String fakePassword = "generated-password";

  @Override
  public StringSecret generateSecret(PasswordGenerationParameters parameters) {
    return new StringSecret("password", fakePassword);
  }

  public String getFakePassword() {
    return fakePassword;
  }
}
