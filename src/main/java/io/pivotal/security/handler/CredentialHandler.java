package io.pivotal.security.handler;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.service.PermissionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Function;

import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;

@Component
public class CredentialHandler {
  private final CredentialDataService credentialDataService;
  private final PermissionService permissionService;

  @Autowired
  public CredentialHandler(CredentialDataService credentialDataService, PermissionService permissionService) {
    this.credentialDataService = credentialDataService;
    this.permissionService = permissionService;
  }

  public void deleteCredential(String credentialName, UserContext userContext) {
    if (!permissionService.hasPermission(userContext.getAclUser(), credentialName, DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    boolean deleteSucceeded = credentialDataService.delete(credentialName);

    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public List<Credential> getNCredentialVersions(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList,
      Integer numberOfVersions
  ) {
    List<Credential> credentials = getAllCredentialVersions(credentialName, userContext, auditRecordParametersList);
    return credentials.subList(0, numberOfVersions);
  }

  public List<Credential> getAllCredentialVersions(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS, credentialName);
    auditRecordParametersList.add(auditRecordParameters);

    List<Credential> credentials = credentialDataService.findAllByName(credentialName);

    // We need this extra check in case permissions aren't being enforced.
    if (credentials.isEmpty() || !permissionService.hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credentials;
  }

  public Credential getMostRecentCredentialVersion(
      String credentialName,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    Credential credential = getVersionByIdentifier(
        credentialName,
        userContext,
        auditRecordParametersList,
        credentialDataService::findMostRecent
    );
    return credential;
  }

  public Credential getCredentialVersion(
      String credentialUuid, UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList
  ) {
    return getVersionByIdentifier(
        credentialUuid,
        userContext,
        auditRecordParametersList,
        credentialDataService::findByUuid
    );
  }

  private Credential getVersionByIdentifier(
      String identifier,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList,
      Function<String, Credential> getFn
  ) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        AuditingOperationCode.CREDENTIAL_ACCESS
    );

    Credential credential = getFn.apply(identifier);

    if (credential != null) {
      eventAuditRecordParameters.setCredentialName(credential.getName());
    }

    auditRecordParametersList.add(eventAuditRecordParameters);

    if (credential == null || !permissionService.hasPermission(userContext.getAclUser(), credential.getName(), READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return credential;
  }
}
