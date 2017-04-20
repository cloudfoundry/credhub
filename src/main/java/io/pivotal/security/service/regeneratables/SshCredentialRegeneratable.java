package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.SshGenerationParameters;

public class SshCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(Credential secret) {
    SshCredential sshSecret = (SshCredential) secret;
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
