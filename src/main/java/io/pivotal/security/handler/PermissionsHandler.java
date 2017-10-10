package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.request.PermissionsRequest;
import io.pivotal.security.service.PermissionCheckingService;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.ACL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_DELETE;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionEventAuditRecordParameters;
import static io.pivotal.security.audit.EventAuditRecordParametersFactory.createPermissionsEventAuditParameters;

@Component
public class PermissionsHandler {

  private final PermissionService permissionService;
  private final PermissionCheckingService permissionCheckingService;
  private final PermissionedCredentialService permissionedCredentialService;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionCheckingService permissionCheckingService,
      PermissionedCredentialService permissionedCredentialService) {
    this.permissionService = permissionService;
    this.permissionCheckingService = permissionCheckingService;
    this.permissionedCredentialService = permissionedCredentialService;
  }

  public PermissionsView getPermissions(String name, UserContext userContext, List<EventAuditRecordParameters> auditRecordParameters) {
    EventAuditRecordParameters eventAuditRecordParameters = new EventAuditRecordParameters(
        ACL_ACCESS, name
    );
    auditRecordParameters.add(eventAuditRecordParameters);
    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(name);

    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    eventAuditRecordParameters.setCredentialName(credentialVersion.getName());
    return new PermissionsView(
        credentialVersion.getName(),
        permissionService.getAccessControlList(userContext, credentialVersion)
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

    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(request.getCredentialName());

    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    for (PermissionEntry permissionEntry : request.getPermissions()) {
      if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, permissionEntry.getActor())) {
        throw new InvalidAclOperationException("error.acl.invalid_update_operation");
      }
    }

    permissionService.saveAccessControlEntries(userContext, credentialVersion, request.getPermissions());
  }

  public void deletePermissionEntry(UserContext userContext,
                                    String credentialName, String actor, List<EventAuditRecordParameters> auditRecordParameters) {

    List<PermissionOperation> operationList = permissionService.getAllowedOperationsForLogging(credentialName, actor);

    if (operationList.size() == 0) {
      auditRecordParameters.add(new EventAuditRecordParameters(ACL_DELETE, credentialName, null, actor));
    } else {
      auditRecordParameters.addAll(createPermissionEventAuditRecordParameters(ACL_DELETE, credentialName, actor, operationList));
    }

    boolean successfullyDeleted = permissionService.deleteAccessControlEntry(userContext, credentialName, actor);

    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }
}
