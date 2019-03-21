package org.cloudfoundry.credhub.handlers;

import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.requests.PermissionsRequest;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.cloudfoundry.credhub.views.PermissionsView;

public class SpyPermissionsHandler implements PermissionsHandler {

  private String findByPathAndActorCalledWithPath;
  private String findByPathAndActorCalledWithActor;
  private PermissionsV2Request putPermissionsCalledWithRequest;
  private PermissionsV2Request putPermissionRequest;
  private PermissionsV2View return_findByPathAndActor;
  private PermissionsV2View return_getPermissions;
  private PermissionsV2View return_writeV2Permissions;
  private PermissionsV2View return_deletePermissions;
  private PermissionsV2View return_putPermissions;
  private PermissionsV2View return_patchPermissions;
  private UUID getPermissionsCalledWithGuid;
  private String deletePermissionsGuid;
  private String putPermissionGuid;
  private String patchPermissionGuid;
  private List<PermissionOperation> patchPermissionsOperations;

  public void setReturn_findByPathAndActor(final PermissionsV2View return_findByPathAndActor) {
    this.return_findByPathAndActor = return_findByPathAndActor;
  }

  public void setReturn_getPermissions(final PermissionsV2View return_getPermissions) {
    this.return_getPermissions = return_getPermissions;
  }

  public void setReturn_deletePermissions(final PermissionsV2View return_deletePermissions) {
    this.return_deletePermissions = return_deletePermissions;
  }

  public void setReturn_patchPermissions(PermissionsV2View permissionsV2View) {
    this.return_patchPermissions = permissionsV2View;
  }

  public void setReturn_putPermissions(PermissionsV2View permissionsV2View) {
    this.return_putPermissions = permissionsV2View;
  }

  public void setReturn_writeV2Permissions(final PermissionsV2View return_writeV2Permissions) {
    this.return_writeV2Permissions = return_writeV2Permissions;
  }

  public void setReturn_writeV2PermissionCalledWithRequest(final PermissionsV2Request request) {
    this.putPermissionsCalledWithRequest = request;
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

  public UUID getGetPermissionsCalledWithGuid() {
    return getPermissionsCalledWithGuid;
  }

  public void setGetPermissionsCalledWithGuid(final UUID guid) {
    this.getPermissionsCalledWithGuid = guid;
  }

  public String getDeletePermissionsGuid() {
    return deletePermissionsGuid;
  }

  public void setDeletePermissionsGuid(final String guid) {
    this.deletePermissionsGuid = guid;
  }

  public String getPatchPermissionGuid() {
    return this.patchPermissionGuid;
  }

  public void setPatchPermissionGuid(final String guid) {
    this.patchPermissionGuid = guid;
  }

  public List<PermissionOperation> getPatchPermissionsOperations() {
    return this.patchPermissionsOperations;
  }

  public void setPatchPermissionsOperations(final List<PermissionOperation> operations) {
    this.patchPermissionsOperations = operations;
  }

  public String getPutPermissionGuid() {
    return this.putPermissionGuid;
  }

  public void setPutPermissionGuid(String guid) {
    this.putPermissionGuid = guid;
  }

  public PermissionsV2Request getPutPermissionsRequest() {
    return this.putPermissionRequest;
  }

  public void setPutPermissionsRequest(final PermissionsV2Request permissionsRequest) {
    this.putPermissionRequest = permissionsRequest;
  }

  public PermissionsV2View getWriteV2Permission() {
    return return_writeV2Permissions;
  }

  public PermissionsV2Request getWriteV2PermissionCalledWithRequest() {
    return putPermissionsCalledWithRequest;
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
  public PermissionsV2View getPermissions(final UUID guid) {
    setGetPermissionsCalledWithGuid(guid);
    return return_getPermissions;
  }

  @Override
  public void deletePermissionEntry(final String credentialName, final String actor) {
  }

  @Override
  public PermissionsV2View deletePermissions(final String guid) {
    setDeletePermissionsGuid(guid);
    return return_deletePermissions;
  }

  @Override
  public PermissionsV2View patchPermissions(final String guid, final List<PermissionOperation> operations) {
    setPatchPermissionGuid(guid);
    setPatchPermissionsOperations(operations);
    return return_patchPermissions;
  }

  @Override
  public PermissionsV2View putPermissions(final String guid, final PermissionsV2Request permissionsRequest) {
    setPutPermissionGuid(guid);
    setPutPermissionsRequest(permissionsRequest);
    return return_putPermissions;
  }

  @Override
  public void writePermissions(final PermissionsRequest request) {
  }

  @Override
  public PermissionsV2View writePermissions(final PermissionsV2Request request) {
    return null;
  }

  @Override
  public PermissionsV2View writeV2Permissions(final PermissionsV2Request permissionsRequest) {
    setReturn_writeV2PermissionCalledWithRequest(permissionsRequest);
    return return_writeV2Permissions;
  }
}
