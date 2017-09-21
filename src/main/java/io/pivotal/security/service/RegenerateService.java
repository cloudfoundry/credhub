package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.CredentialGenerator;
import io.pivotal.security.generator.PasswordCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.generator.UserGenerator;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.service.regeneratables.CertificateCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.NotRegeneratable;
import io.pivotal.security.service.regeneratables.PasswordCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.Regeneratable;
import io.pivotal.security.service.regeneratables.RsaCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.SshCredentialRegeneratable;
import io.pivotal.security.service.regeneratables.UserCredentialRegeneratable;
import io.pivotal.security.view.BulkRegenerateResults;
import io.pivotal.security.view.CredentialView;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;

@Service
public class RegenerateService {

  private CredentialDataService credentialDataService;
  private Map<String, Supplier<Regeneratable>> regeneratableTypeProducers;
  private CredentialService credentialService;
  private final PermissionService permissionService;
  private PasswordCredentialGenerator passwordCredentialGenerator;
  private UserGenerator userGenerator;
  private SshGenerator sshGenerator;
  private RsaGenerator rsaGenerator;
  private CertificateGenerator certificateGenerator;
  private Map<String, CredentialGenerator> credentialGenerators;

  RegenerateService(
      CredentialDataService credentialDataService,
      CredentialService credentialService,
      PermissionService permissionService,
      PasswordCredentialGenerator passwordCredentialGenerator,
      UserGenerator userGenerator,
      SshGenerator sshGenerator,
      RsaGenerator rsaGenerator,
      CertificateGenerator certificateGenerator) {
    this.credentialDataService = credentialDataService;
    this.credentialService = credentialService;
    this.permissionService = permissionService;
    this.credentialService = credentialService;
    this.passwordCredentialGenerator = passwordCredentialGenerator;
    this.userGenerator = userGenerator;
    this.sshGenerator = sshGenerator;
    this.rsaGenerator = rsaGenerator;
    this.certificateGenerator = certificateGenerator;

    this.regeneratableTypeProducers = new HashMap<>();
    this.regeneratableTypeProducers.put("password", PasswordCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("user", UserCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("ssh", SshCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("rsa", RsaCredentialRegeneratable::new);
    this.regeneratableTypeProducers.put("certificate", CertificateCredentialRegeneratable::new);

    this.credentialGenerators = new HashMap<>();
    this.credentialGenerators.put("password", this.passwordCredentialGenerator);
    this.credentialGenerators.put("user", this.userGenerator);
    this.credentialGenerators.put("ssh", this.sshGenerator);
    this.credentialGenerators.put("rsa", this.rsaGenerator);
    this.credentialGenerators.put("certificate", this.certificateGenerator);
  }

  public CredentialView performRegenerate(
      String credentialName,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    Credential credential = credentialDataService.findMostRecent(credentialName);
    if (credential == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
      throw new EntryNotFoundException("error.credential.invalid_access");
    } else if (!permissionService.hasPermission(userContext.getAclUser(), credentialName, PermissionOperation.WRITE)){
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
      throw new PermissionException("error.credential.invalid_access");
    }

    Regeneratable regeneratable = regeneratableTypeProducers
        .getOrDefault(credential.getCredentialType(), NotRegeneratable::new)
        .get();

    if (credential instanceof PasswordCredential && ((PasswordCredential) credential).getGenerationParameters() == null) {
      auditRecordParameters.add(new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName));
    }

    final BaseCredentialGenerateRequest generateRequest = regeneratable
        .createGenerateRequest(credential);

    final CredentialValue credentialValue = generateCredential(generateRequest);

    StringGenerationParameters generationParameters = null;
    if (generateRequest instanceof PasswordGenerateRequest) {
      generationParameters = ((PasswordGenerateRequest) generateRequest).getGenerationParameters();
    }
    if (generateRequest instanceof UserGenerateRequest) {
      generationParameters = ((UserGenerateRequest) generateRequest).getUserCredentialGenerationParameters();
    }

    return credentialService.save(
        generateRequest.getName(),
        generateRequest.getType(),
        credentialValue,
        generationParameters,
        generateRequest.getAdditionalPermissions(),
        generateRequest.isOverwrite(),
        userContext,
        currentUserPermissionEntry,
        auditRecordParameters
    );
  }

  public BulkRegenerateResults performBulkRegenerate(
      String signerName,
      UserContext userContext,
      PermissionEntry currentUserPermissionEntry,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    if (!permissionService.hasPermission(userContext.getAclUser(), signerName, PermissionOperation.READ)) {
      throw new PermissionException("error.credential.invalid_access");
    }

    BulkRegenerateResults results = new BulkRegenerateResults();
    List<String> certificateNames = credentialDataService.findAllCertificateCredentialsByCaName(signerName);

    final HashSet<String> credentialNamesSet = new HashSet<>(certificateNames);
    for (String name : credentialNamesSet) {
      this.performRegenerate(name, userContext, currentUserPermissionEntry,
          auditRecordParameters);
    }

    results.setRegeneratedCredentials(credentialNamesSet);
    return results;
  }

  private CredentialValue generateCredential(BaseCredentialGenerateRequest generateRequest) {
    CredentialGenerator generator = credentialGenerators.get(generateRequest.getType());
    return generator.generateCredential(generateRequest.getDomainGenerationParameters());
  }
}
