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

import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
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
    if (!permissionService.hasPermission(userContext.getAclUser(), credentialName, DELETE)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    boolean deleteSucceeded = credentialDataService.delete(credentialName);

    if (!deleteSucceeded) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public DataResponse getAllCredentialVersions(
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList,
      String credentialName
  ) {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters(AuditingOperationCode.CREDENTIAL_ACCESS, credentialName);
    auditRecordParametersList.add(auditRecordParameters);

    List<Credential> credentials = credentialDataService.findAllByName(credentialName);

    // We need this extra check in case permissions aren't being enforced.
    if (credentials.isEmpty() || !permissionService.hasPermission(userContext.getAclUser(), credentialName, READ)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return DataResponse.fromEntity(credentials);
  }

  public DataResponse getMostRecentCredentialVersion(
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList,
      String credentialName
  ) {
    Credential credential = getVersionByIdentifier(
        userContext,
        auditRecordParametersList,
        credentialName,
        credentialDataService::findMostRecent
    );
    return DataResponse.fromEntity(singletonList(credential));
  }

  public CredentialView getCredentialVersion(
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList,
      String credentialUuid
  ) {
    return CredentialView.fromEntity(getVersionByIdentifier(
        userContext,
        auditRecordParametersList,
        credentialUuid,
        credentialDataService::findByUuid
    ));
  }

  private Credential getVersionByIdentifier(
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParametersList,
      String identifier,
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
