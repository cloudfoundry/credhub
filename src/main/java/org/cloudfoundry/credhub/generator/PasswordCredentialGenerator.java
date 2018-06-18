package org.cloudfoundry.credhub.generator;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.SecretKeyHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Random;

// Can't be named PasswordGenerator or Spring won't know how to autowire it.
@Component
public class PasswordCredentialGenerator implements CredentialGenerator<StringCredentialValue> {

  private final PassayStringCredentialGenerator passayStringCredentialGenerator;

  @Autowired
  PasswordCredentialGenerator(PassayStringCredentialGenerator passayStringCredentialGenerator) {
    this.passayStringCredentialGenerator = passayStringCredentialGenerator;
  }

  @Override
  public StringCredentialValue generateCredential(GenerationParameters stringGenerationParameters) {
    StringGenerationParameters parameters = (StringGenerationParameters) stringGenerationParameters;

    if (parameters.isSecretKeyMode()) {
      String secretKey = SecretKeyHelper.generateSecretKey(parameters.getLength());
      return new StringCredentialValue(secretKey);
    }

    return passayStringCredentialGenerator.generateCredential(parameters);
  }
}