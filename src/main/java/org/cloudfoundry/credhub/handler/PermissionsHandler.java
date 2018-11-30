package org.cloudfoundry.credhub.handler;

import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.request.PermissionsRequest;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.cloudfoundry.credhub.view.PermissionsV2View;
import org.cloudfoundry.credhub.view.PermissionsView;

public interface PermissionsHandler {

  PermissionsView getPermissions(String name);

  void setPermissions(PermissionsRequest request);

  void deletePermissionEntry(String credentialName, String actor);

  PermissionsV2View setPermissions(PermissionsV2Request request);

  PermissionsV2View getPermissions(UUID guid);

  PermissionsV2View putPermissions(String guid, PermissionsV2Request permissionsRequest);

  PermissionsV2View patchPermissions(String guid, List<PermissionOperation> operations);

  PermissionsV2View setV2Permissions(PermissionsV2Request permissionsRequest);

  PermissionsV2View deletePermissions(String guid);

  PermissionsV2View findByPathAndActor(String path, String actor);
}
