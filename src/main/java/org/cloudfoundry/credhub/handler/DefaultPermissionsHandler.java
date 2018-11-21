package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
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
import java.util.UUID;

@Component
public class DefaultPermissionsHandler implements PermissionsHandler {

  public static final String INVALID_NUMBER_OF_PERMISSIONS = "Can set one permission per call";
  private final PermissionService permissionService;
  private final PermissionedCredentialService permissionedCredentialService;
  private final CEFAuditRecord auditRecord;

  DefaultPermissionsHandler(
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
    List<PermissionData> permissionDatas = permissionService.savePermissionsForUser(Collections.singletonList(permission));

    if (permissionDatas.size() == 1) {
      PermissionData perm = permissionDatas.get(0);
      return new PermissionsV2View(perm.getPath(),perm.generateAccessControlOperations(),perm.getActor(), perm.getUuid());
    } else {
      throw new IllegalArgumentException(INVALID_NUMBER_OF_PERMISSIONS);
    }
  }

  public PermissionsV2View getPermissions(UUID guid) {

    final PermissionData permission = permissionService.getPermissions(guid);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
        permission.getActor(), guid);
  }

  public PermissionsV2View putPermissions(String guid, PermissionsV2Request permissionsRequest) {
    final PermissionData permission = permissionService.putPermissions(guid, permissionsRequest);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
        permission.getActor(), permission.getUuid());
  }

  public PermissionsV2View patchPermissions(String guid, List<PermissionOperation> operations) {
    PermissionData permission = permissionService.patchPermissions(guid, operations);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
        permission.getActor(), permission.getUuid());
  }

  public PermissionsV2View setV2Permissions(PermissionsV2Request permissionsRequest) {
    final PermissionData permission = permissionService.saveV2Permissions(permissionsRequest);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
        permission.getActor(), permission.getUuid());
  }

  public PermissionsV2View deletePermissions(String guid) {
    PermissionData permission = permissionService.deletePermissions(guid);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
        permission.getActor(), permission.getUuid());
  }

  public PermissionsV2View findByPathAndActor(String path, String actor) {
    PermissionData permissionData = permissionService.findByPathAndActor(path, actor);
    if(permissionData == null) {
      throw new EntryNotFoundException("error.permission.invalid_access");
    }

    return new PermissionsV2View(permissionData.getPath(), permissionData.generateAccessControlOperations(),
      permissionData.getActor(), permissionData.getUuid());
  }
}
