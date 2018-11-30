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
  private PermissionsV2View return_findByPathAndActor;

  public void setReturn_findByPathAndActor(PermissionsV2View return_findByPathAndActor) {
    this.return_findByPathAndActor = return_findByPathAndActor;
  }

  public String getFindByPathAndActorCalledWithPath() {
    return findByPathAndActorCalledWithPath;
  }

  public void setFindByPathAndActorCalledWithPath(String findByPathAndActorCalledWithPath) {
    this.findByPathAndActorCalledWithPath = findByPathAndActorCalledWithPath;
  }

  public String getFindByPathAndActorCalledWithActor() {
    return findByPathAndActorCalledWithActor;
  }

  public void setFindByPathAndActorCalledWithActor(String findByPathAndActorCalledWithActor) {
    this.findByPathAndActorCalledWithActor = findByPathAndActorCalledWithActor;
  }

  @Override
  public PermissionsV2View findByPathAndActor(String path, String actor) {
    setFindByPathAndActorCalledWithPath(path);
    setFindByPathAndActorCalledWithActor(actor);
    return return_findByPathAndActor;
  }

  @Override
  public PermissionsView getPermissions(String name) {
    return null;
  }

  @Override
  public void setPermissions(PermissionsRequest request) {
  }

  @Override
  public void deletePermissionEntry(String credentialName, String actor) {
  }

  @Override
  public PermissionsV2View setPermissions(PermissionsV2Request request) {
    return null;
  }

  @Override
  public PermissionsV2View getPermissions(UUID guid) {
    return null;
  }

  @Override
  public PermissionsV2View putPermissions(String guid, PermissionsV2Request permissionsRequest) {
    return null;
  }

  @Override
  public PermissionsV2View patchPermissions(String guid, List<PermissionOperation> operations) {
    return null;
  }

  @Override
  public PermissionsV2View setV2Permissions(PermissionsV2Request permissionsRequest) {
    return null;
  }

  @Override
  public PermissionsV2View deletePermissions(String guid) {
    return null;
  }
}
