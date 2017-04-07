package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.ErrorResponseService;
import io.pivotal.security.service.GenerateService;
import org.springframework.http.ResponseEntity;

public class SshSecret implements Regeneratable {

  private GenerateService generateService;

  public SshSecret(ErrorResponseService responseService, GenerateService generateService) {
    this.generateService = generateService;
  }

  @Override
  public ResponseEntity regenerate(NamedSecret secret, AuditRecordBuilder auditRecordBuilder) {
    NamedSshSecret sshSecret = (NamedSshSecret) secret;
    SshGenerateRequest generateRequest = new SshGenerateRequest();

    generateRequest.setName(sshSecret.getName());
    generateRequest.setType(sshSecret.getSecretType());
    SshGenerationParameters generationParameters = new SshGenerationParameters();
    generationParameters.setSshComment(sshSecret.getComment());
    generateRequest.setGenerationParameters(generationParameters);

    return generateService.performGenerate(auditRecordBuilder, generateRequest);
  }
}
