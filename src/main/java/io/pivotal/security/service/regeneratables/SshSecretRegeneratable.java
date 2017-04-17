package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.SshGenerationParameters;

public class SshSecretRegeneratable implements Regeneratable {

  @Override
  public BaseSecretGenerateRequest createGenerateRequest(NamedSecret secret) {
    NamedSshSecret sshSecret = (NamedSshSecret) secret;
    SshGenerateRequest generateRequest = new SshGenerateRequest();

    generateRequest.setName(sshSecret.getName());
    generateRequest.setType(sshSecret.getSecretType());
    SshGenerationParameters generationParameters = new SshGenerationParameters();
    generationParameters.setSshComment(sshSecret.getComment());
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
