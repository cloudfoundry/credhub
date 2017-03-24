package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import org.springframework.context.ApplicationContext;

import java.util.List;

public class PasswordGenerateRequest extends BaseSecretGenerateRequest {
  public static final List<AccessControlEntry> NULL_ACCESS_CONTROL_ENTRIES = null;
  @JsonProperty("parameters")
  private PasswordGenerationParameters generationParameters;

  public PasswordGenerationParameters getGenerationParameters() {
    if (generationParameters == null) {
      generationParameters = new PasswordGenerationParameters();
    }
    return generationParameters;
  }

  @Override
  public void validate() {
    super.validate();

    getGenerationParameters().validate();
  }

  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor, ApplicationContext applicationContext) {
    // Reluctantly use app context as @Autowired doesn't work here
    PassayStringSecretGenerator passayStringSecretGenerator = applicationContext.getBean(PassayStringSecretGenerator.class);
    String newPassword = passayStringSecretGenerator.generateSecret(getGenerationParameters()).getPassword();
    return NamedPasswordSecret.createNewVersion((NamedPasswordSecret) existing, getName(), newPassword, getGenerationParameters(), encryptor, NULL_ACCESS_CONTROL_ENTRIES);
  }
}
