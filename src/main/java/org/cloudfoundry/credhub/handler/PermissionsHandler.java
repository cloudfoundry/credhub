package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.cloudfoundry.credhub.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

@Component
public class PermissionsHandler {

  private final PermissionService permissionService;
  private final PermissionedCredentialService permissionedCredentialService;
  private final CEFAuditRecord auditRecord;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionedCredentialService permissionedCredentialService,
      CEFAuditRecord auditRecord) {
    this.permissionService = permissionService;
    this.permissionedCredentialService = permissionedCredentialService;
    this.auditRecord = auditRecord;
  }

  public PermissionsView getPermissions(String name) {
    CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(name);
    final List<PermissionEntry> permissions = permissionService.getPermissions(credentialVersion);
    return new PermissionsView(credentialVersion.getName(), permissions);
  }

  public void setPermissions(PermissionsRequest request) {
    for(PermissionEntry entry : request.getPermissions()){
      entry.setPath(request.getCredentialName());
    }
    permissionService.savePermissionsForUser(request.getPermissions());
  }

  public void deletePermissionEntry(String credentialName, String actor) {
    boolean successfullyDeleted = permissionService.deletePermissions(credentialName, actor);
    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  public PermissionsV2View setPermissions(PermissionsV2Request request) {

    PermissionEntry permission = new PermissionEntry(request.getActor(), request.getPath(), request.getOperations());
    permissionService.savePermissionsForUser(Collections.singletonList(permission));

    return new PermissionsV2View(request.getPath(),request.getOperations(),request.getActor());
  }
}
