package io.pivotal.security.handler;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.DataResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Function;

import static java.util.Collections.singletonList;

@Component
public class CredentialHandler {
  private final CredentialDataService credentialDataService;
  private final PermissionService permissionService;

  @Autowired
  public CredentialHandler(CredentialDataService credentialDataService, PermissionService permissionService) {
    this.credentialDataService = credentialDataService;
    this.permissionService = permissionService;
  }

  public void deleteCredential(UserContext userContext, String credentialName) {
    Credential credential = credentialDataService.findMostRecent(credentialName);

    if (credential != null && !permissionService.hasCredentialDeletePermission(userContext, credential)) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    boolean deleteSucceeded = credentialDataService.delete(credentialName);

    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential_not_found");
    }
  }

  public DataResponse getAllCredentialVersions(
      UserContext userContext,
      EventAuditRecordParameters auditRecordParameters, String credentialName
  ) {
    auditRecordParameters.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);
    auditRecordParameters.setCredentialName(credentialName);

    List<Credential> credentials = credentialDataService.findAllByName(credentialName);

    if (credentials.isEmpty() || !permissionService.hasCredentialReadPermission(userContext, credentials.get(0))) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    return DataResponse.fromEntity(credentials);
  }

  public DataResponse getMostRecentCredentialVersion(
      UserContext userContext,
      EventAuditRecordParameters auditRecordParameters,
      String credentialName
  ) {
    Credential credential = getVersionByIdentifier(
        userContext,
        auditRecordParameters,
        credentialName,
        credentialDataService::findMostRecent
    );
    return DataResponse.fromEntity(singletonList(credential));
  }

  public CredentialView getCredentialVersion(
      UserContext userContext,
      EventAuditRecordParameters auditRecordParameters,
      String credentialUuid
  ) {
    return CredentialView.fromEntity(getVersionByIdentifier(
        userContext,
        auditRecordParameters,
        credentialUuid,
        credentialDataService::findByUuid
    ));
  }

  private Credential getVersionByIdentifier(
      UserContext userContext,
      EventAuditRecordParameters auditRecordParameters,
      String identifier,
      Function<String, Credential> getFn
  ) {
    auditRecordParameters.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);

    Credential credential = getFn.apply(identifier);

    if (credential != null) {
      auditRecordParameters.setCredentialName(credential.getName());
    }

    if (credential == null || !permissionService.hasCredentialReadPermission(userContext, credential)) {
      throw new EntryNotFoundException("error.credential_not_found");
    }

    return credential;
  }
}
