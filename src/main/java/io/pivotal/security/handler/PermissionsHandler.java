package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionsRequest;
import io.pivotal.security.service.PermissionCheckingService;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;

@Component
public class PermissionsHandler {

  private final PermissionService permissionService;
  private final PermissionCheckingService permissionCheckingService;
  private final CredentialDataService credentialDataService;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionCheckingService permissionCheckingService,
      CredentialDataService credentialDataService
  ) {
    this.permissionService = permissionService;
    this.permissionCheckingService = permissionCheckingService;
    this.credentialDataService = credentialDataService;
  }

  public PermissionsView getPermissions(String name, UserContext userContext, List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        ACL_ACCESS, name
    );
    auditRecordParameters.add(eventAuditRecordParameters);

    final Credential credential = credentialDataService.find(name);

    if (credential == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    eventAuditRecordParameters.setCredentialName(credential.getName());
    return new PermissionsView(
        credential.getName(),
        permissionService.getAccessControlList(userContext, credential)
    );
  }

  public void setPermissions(
      PermissionsRequest request,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    auditRecordParameters.addAll(createPermissionsEventAuditParameters(
        ACL_UPDATE,
        request.getCredentialName(),
        request.getPermissions())
    );
    final Credential credential = credentialDataService.find(request.getCredentialName());

    // We need to verify that the credential exists in case ACL enforcement is off
    if (credential == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    for (PermissionEntry permissionEntry : request.getPermissions()) {
      if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, permissionEntry.getActor())) {
        throw new InvalidAclOperationException("error.acl.invalid_update_operation");
      }
    }

    permissionService.saveAccessControlEntries(userContext, credential, request.getPermissions());
  }

  public void deletePermissionEntry(UserContext userContext,
      String credentialName, String actor) {

    boolean successfullyDeleted = permissionService
        .deleteAccessControlEntry(userContext, credentialName, actor);

    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }
}
