package org.cloudfoundry.credhub.handler;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.DefaultPermissionedCredentialService;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.cloudfoundry.credhub.view.PermissionsView;

@Component
public class DefaultPermissionsHandler implements PermissionsHandler {

  public static final String INVALID_NUMBER_OF_PERMISSIONS = "Can set one permission per call";
  private final PermissionService permissionService;
  private final PermissionedCredentialService permissionedCredentialService;

  DefaultPermissionsHandler(
    final PermissionService permissionService,
    final PermissionedCredentialService permissionedCredentialService
  ) {
    super();
    this.permissionService = permissionService;
    this.permissionedCredentialService = permissionedCredentialService;
  }

  @Override
  public PermissionsView getPermissions(final String name) {
    final CredentialVersion credentialVersion = permissionedCredentialService.findMostRecent(name);
    final List<PermissionEntry> permissions = permissionService.getPermissions(credentialVersion);
    return new PermissionsView(credentialVersion.getName(), permissions);
  }

  @Override
  public void writePermissions(final PermissionsRequest request) {
    for (final PermissionEntry entry : request.getPermissions()) {
      entry.setPath(request.getCredentialName());
    }
    permissionService.savePermissionsForUser(request.getPermissions());
  }

  @Override
  public void deletePermissionEntry(final String credentialName, final String actor) {
    final boolean successfullyDeleted = permissionService.deletePermissions(credentialName, actor);
    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }

  @Override
  public PermissionsV2View writePermissions(final PermissionsV2Request request) {

    final PermissionEntry permission = new PermissionEntry(request.getActor(), request.getPath(), request.getOperations());
    final List<PermissionData> permissionDatas = permissionService.savePermissionsForUser(Collections.singletonList(permission));

    if (permissionDatas.size() == 1) {
      final PermissionData perm = permissionDatas.get(0);
      return new PermissionsV2View(perm.getPath(), perm.generateAccessControlOperations(), perm.getActor(), perm.getUuid());
    } else {
      throw new IllegalArgumentException(INVALID_NUMBER_OF_PERMISSIONS);
    }
  }

  @Override
  public PermissionsV2View getPermissions(final UUID guid) {

    final PermissionData permission = permissionService.getPermissions(guid);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
      permission.getActor(), guid);
  }

  @Override
  public PermissionsV2View putPermissions(final String guid, final PermissionsV2Request permissionsRequest) {
    final PermissionData permission = permissionService.putPermissions(guid, permissionsRequest);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
      permission.getActor(), permission.getUuid());
  }

  @Override
  public PermissionsV2View patchPermissions(final String guid, final List<PermissionOperation> operations) {
    final PermissionData permission = permissionService.patchPermissions(guid, operations);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
      permission.getActor(), permission.getUuid());
  }

  @Override
  public PermissionsV2View writeV2Permissions(final PermissionsV2Request permissionsRequest) {
    final PermissionData permission = permissionService.saveV2Permissions(permissionsRequest);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
      permission.getActor(), permission.getUuid());
  }

  @Override
  public PermissionsV2View deletePermissions(final String guid) {
    final PermissionData permission = permissionService.deletePermissions(guid);
    return new PermissionsV2View(permission.getPath(), permission.generateAccessControlOperations(),
      permission.getActor(), permission.getUuid());
  }

  @Override
  public PermissionsV2View findByPathAndActor(final String path, final String actor) {
    final PermissionData permissionData = permissionService.findByPathAndActor(path, actor);
    if (permissionData == null) {
      throw new EntryNotFoundException("error.permission.invalid_access");
    }

    return new PermissionsV2View(permissionData.getPath(), permissionData.generateAccessControlOperations(),
      permissionData.getActor(), permissionData.getUuid());
  }
}
