package org.cloudfoundry.credhub.handlers;

import java.util.List;
import java.util.UUID;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.requests.PermissionsRequest;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.cloudfoundry.credhub.views.PermissionsV2View;
import org.cloudfoundry.credhub.views.PermissionsView;

public interface PermissionsHandler {

  PermissionsView getPermissions(String name);

  void writePermissions(PermissionsRequest request);

  void deletePermissionEntry(String credentialName, String actor);

  PermissionsV2View writePermissions(PermissionsV2Request request);

  PermissionsV2View getPermissions(UUID guid);

  PermissionsV2View putPermissions(String guid, PermissionsV2Request permissionsRequest);

  PermissionsV2View patchPermissions(String guid, List<PermissionOperation> operations);

  PermissionsV2View writeV2Permissions(PermissionsV2Request permissionsRequest);

  PermissionsV2View deletePermissions(String guid);

  PermissionsV2View findByPathAndActor(String path, String actor);
}
