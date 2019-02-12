package org.cloudfoundry.credhub.handler;

import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.cloudfoundry.credhub.view.PermissionsView;

public class SpyPermissionsHandler implements PermissionsHandler {

  private String findByPathAndActorCalledWithPath;
  private String findByPathAndActorCalledWithActor;
  private PermissionsV2Request putPermissionsCalledWithRequest;
  private PermissionsV2View return_findByPathAndActor;
  private PermissionsV2View return_getPermissions;
  private PermissionsV2View return_writeV2Permissions;
  private UUID getPermissionsCalledWithGuid;

  public void setReturn_findByPathAndActor(final PermissionsV2View return_findByPathAndActor) {
    this.return_findByPathAndActor = return_findByPathAndActor;
  }

  public void setReturn_getPermissions(final PermissionsV2View return_getPermissions) {
    this.return_getPermissions = return_getPermissions;
  }

  public String getFindByPathAndActorCalledWithPath() {
    return findByPathAndActorCalledWithPath;
  }

  public void setFindByPathAndActorCalledWithPath(final String findByPathAndActorCalledWithPath) {
    this.findByPathAndActorCalledWithPath = findByPathAndActorCalledWithPath;
  }

  public String getFindByPathAndActorCalledWithActor() {
    return findByPathAndActorCalledWithActor;
  }

  public void setFindByPathAndActorCalledWithActor(final String findByPathAndActorCalledWithActor) {
    this.findByPathAndActorCalledWithActor = findByPathAndActorCalledWithActor;
  }

  public void setGetPermissionsCalledWithGuid(final UUID guid) {
    this.getPermissionsCalledWithGuid = guid;
  }

  public void setreturn_writeV2PermissionCalledWithRequest(final PermissionsV2Request request) {
    this.putPermissionsCalledWithRequest = request;
  }

  public void setreturn_writeV2Permissions(final PermissionsV2View return_writeV2Permissions) {
    this.return_writeV2Permissions = return_writeV2Permissions;
  }

  public UUID getGetPermissionsCalledWithGuid() {
    return getPermissionsCalledWithGuid;
  }

  @Override
  public PermissionsV2View findByPathAndActor(final String path, final String actor) {
    setFindByPathAndActorCalledWithPath(path);
    setFindByPathAndActorCalledWithActor(actor);
    return return_findByPathAndActor;
  }

  @Override
  public PermissionsView getPermissions(final String name) {
    return null;
  }

  @Override
  public void writePermissions(final PermissionsRequest request) {
  }

  @Override
  public void deletePermissionEntry(final String credentialName, final String actor) {
  }

  @Override
  public PermissionsV2View writePermissions(final PermissionsV2Request request) { return null; }

  @Override
  public PermissionsV2View getPermissions(final UUID guid) {
    setGetPermissionsCalledWithGuid(guid);
    return return_getPermissions;
  }

  @Override
  public PermissionsV2View putPermissions(final String guid, final PermissionsV2Request permissionsRequest) {
    return null;
  }

  @Override
  public PermissionsV2View patchPermissions(final String guid, final List<PermissionOperation> operations) {
    return null;
  }

  @Override
  public PermissionsV2View writeV2Permissions(final PermissionsV2Request permissionsRequest) {
    setreturn_writeV2PermissionCalledWithRequest(permissionsRequest);
    return return_writeV2Permissions;
  }

  @Override
  public PermissionsV2View deletePermissions(final String guid) {
    return null;
  }

  public PermissionsV2Request getWriteV2PermissionCalledWithRequest() {
    return putPermissionsCalledWithRequest;
  }
}
