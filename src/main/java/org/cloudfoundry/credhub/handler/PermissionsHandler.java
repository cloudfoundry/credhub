package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.PermissionsView;
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

  public PermissionsView getPermissions(String name,
      List<EventAuditRecordParameters> auditRecordParameters) {
    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(name);
    final List<PermissionEntry> permissions = permissionService.getPermissions(credentialVersion, auditRecordParameters, name);
    return new PermissionsView(credentialVersion.getName(), permissions);
  }

  public void setPermissions(
      PermissionsRequest request,
      List<EventAuditRecordParameters> auditRecordParameters
  ) {
    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(request.getCredentialName());
    permissionService.savePermissions(credentialVersion, request.getPermissions(), auditRecordParameters, false, request.getCredentialName());
  }

  public void deletePermissionEntry(String credentialName, String actor, List<EventAuditRecordParameters> auditRecordParameters) {
    boolean successfullyDeleted = permissionService.deletePermissions(credentialName, actor, auditRecordParameters);
    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }
}
