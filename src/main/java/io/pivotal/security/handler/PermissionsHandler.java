package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionsRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PermissionsHandler {

  private final PermissionService permissionService;
  private final PermissionedCredentialService permissionedCredentialService;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionedCredentialService permissionedCredentialService) {
    this.permissionService = permissionService;
    this.permissionedCredentialService = permissionedCredentialService;
  }

  public PermissionsView getPermissions(String name, UserContext userContext, List<EventAuditRecordParameters> auditRecordParameters) {
    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(name);
    final List<PermissionEntry> accessControlList = permissionService.getAccessControlList(userContext, credentialVersion, auditRecordParameters, name);
    return new PermissionsView(credentialVersion.getName(), accessControlList);
  }

  public void setPermissions(
      PermissionsRequest request,
      UserContext userContext,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(request.getCredentialName());
    permissionService.saveAccessControlEntries(userContext, credentialVersion, request.getPermissions(), auditRecordParameters, false, request.getCredentialName());
  }

  public void deletePermissionEntry(UserContext userContext,
                                    String credentialName, String actor, List<EventAuditRecordParameters> auditRecordParameters) {
    boolean successfullyDeleted = permissionService.deleteAccessControlEntry(userContext, credentialName, actor, auditRecordParameters);
    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }
}
