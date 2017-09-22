package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.CredentialGenerator;
import io.pivotal.security.generator.PasswordCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.generator.UserGenerator;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.service.CredentialService;
import io.pivotal.security.view.CredentialView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class GenerateHandler {

  private PasswordCredentialGenerator passwordCredentialGenerator;
  private UserGenerator userGenerator;
  private SshGenerator sshGenerator;
  private RsaGenerator rsaGenerator;
  private CertificateGenerator certificateGenerator;
  private final CredentialService credentialService;
  private Map<String, CredentialGenerator> credentialGenerators;

  @Autowired
  public GenerateHandler(
      CredentialService credentialService,
      PasswordCredentialGenerator passwordCredentialGenerator,
      UserGenerator userGenerator, SshGenerator sshGenerator,
      RsaGenerator rsaGenerator,
      CertificateGenerator certificateGenerator) {
    this.credentialService = credentialService;
    this.passwordCredentialGenerator = passwordCredentialGenerator;
    this.userGenerator = userGenerator;
    this.sshGenerator = sshGenerator;
    this.rsaGenerator = rsaGenerator;
    this.certificateGenerator = certificateGenerator;

    this.credentialGenerators = new HashMap<>();
    this.credentialGenerators.put("password", this.passwordCredentialGenerator);
    this.credentialGenerators.put("user", this.userGenerator);
    this.credentialGenerators.put("ssh", this.sshGenerator);
    this.credentialGenerators.put("rsa", this.rsaGenerator);
    this.credentialGenerators.put("certificate", this.certificateGenerator);
  }

  public CredentialView handle(
      BaseCredentialGenerateRequest requestBody,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {

    CredentialValue value = generateCredential(requestBody, userContext);

    StringGenerationParameters generationParameters = null;
    if (requestBody instanceof PasswordGenerateRequest) {
      generationParameters = ((PasswordGenerateRequest) requestBody).getGenerationParameters();
    }

    if (requestBody instanceof UserGenerateRequest) {
      generationParameters = ((UserGenerateRequest) requestBody)
          .getUserCredentialGenerationParameters();
    }

    return credentialService.save(
        requestBody.getName(),
        requestBody.getType(),
        value,
        generationParameters,
        requestBody.getAdditionalPermissions(),
        requestBody.isOverwrite(),
        userContext,
        currentUserPermissionEntry,
        auditRecordParameters
    );
  }

  private CredentialValue generateCredential(BaseCredentialGenerateRequest requestBody, UserContext userContext) {
    CredentialGenerator generator = credentialGenerators.get(requestBody.getType());
    return generator.generateCredential(requestBody.getDomainGenerationParameters(), userContext);
  }
}
