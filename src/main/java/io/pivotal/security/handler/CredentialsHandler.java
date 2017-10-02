package io.pivotal.security.handler;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.pivotal.security.request.PermissionOperation.READ;

@Component
public class CredentialsHandler {
  private final PermissionedCredentialService credentialService;
  private final PermissionService permissionService;

  @Autowired
  public CredentialsHandler(PermissionedCredentialService credentialService,
      PermissionService permissionService) {
    this.credentialService = credentialService;
    this.permissionService = permissionService;
  }

  public void deleteCredential(String credentialName, UserContext userContext) {
    boolean deleteSucceeded = credentialService.delete(userContext, credentialName);

    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public List<Credential> getNCredentialVersions(
      String credentialName,
      Integer numberOfVersions, UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_ACCESS, credentialName);
    auditRecordParametersList.add(auditRecordParameters);

    List<Credential> credentials;
    if (numberOfVersions != null && numberOfVersions < 0) {
      throw new InvalidQueryParameterException("error.invalid_query_parameter", "versions");
    }

    if (numberOfVersions == null) {
      credentials = credentialService.findAllByName(userContext, credentialName);
    } else {
      credentials = credentialService.findNByName(userContext, credentialName, numberOfVersions);
    }

    if (credentials.isEmpty()) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    return credentials;
  }

  public List<Credential> getAllCredentialVersions(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return getNCredentialVersions(credentialName, null, userContext, auditRecordParametersList);
  }

  public Credential getMostRecentCredentialVersion(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    Credential credential =
        getNCredentialVersions(credentialName, 1, userContext, auditRecordParametersList)
            .get(0);

    return credential;
  }

  public Credential getCredentialVersionByUUID(
      String credentialUUID,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_ACCESS
    );

    Credential credential = credentialService.findByUuid(credentialUUID);

    if (credential != null) {
      eventAuditRecordParameters.setCredentialName(credential.getName());
    }

    auditRecordParametersList.add(eventAuditRecordParameters);

    if (credential == null ||
        !permissionService.hasPermission(userContext.getAclUser(), credential.getName(), READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credential;
  }
}
