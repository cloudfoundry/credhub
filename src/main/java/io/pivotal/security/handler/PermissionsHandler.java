package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialNameDataService;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PermissionsHandler {
  private final PermissionService permissionService;
  private final PermissionsDataService permissionsDataService;
  private final CredentialNameDataService credentialNameDataService;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionsDataService permissionsDataService,
      CredentialNameDataService credentialNameDataService
  ) {
    this.permissionService = permissionService;
    this.permissionsDataService = permissionsDataService;
    this.credentialNameDataService = credentialNameDataService;
  }

  public PermissionsView getPermissions(UserContext userContext, String name) {
    try {
      final CredentialName credentialName = credentialNameDataService.findOrThrow(name);

      permissionService.verifyAclReadPermission(userContext, name);

      return new PermissionsView(
          credentialName.getName(),
          permissionsDataService.getAccessControlList(credentialName)
      );
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }
  }

  public PermissionsView setPermissions(UserContext userContext, String name, List<PermissionEntry> permissionEntryList) {
    final CredentialName credentialName = credentialNameDataService.find(name);

    // We need to verify that the credential exists in case ACL enforcement is off
    if (credentialName == null || !permissionService.hasAclWritePermission(userContext, name)) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    for (PermissionEntry permissionEntry : permissionEntryList) {
      if(!permissionService.validAclUpdateOperation(userContext, permissionEntry.getActor())) {
        throw new InvalidAclOperationException("error.acl.invalid_update_operation");
      }
    }

    permissionsDataService
        .saveAccessControlEntries(credentialName, permissionEntryList);

    return new PermissionsView(credentialName.getName(), permissionsDataService.getAccessControlList(credentialName));
  }

  public void deletePermissionEntry(UserContext userContext, String credentialName, String actor) {
    if (!permissionService.hasAclWritePermission(userContext, credentialName)) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    if(!permissionService.validAclUpdateOperation(userContext, actor)) {
      throw new InvalidAclOperationException("error.acl.invalid_update_operation");
    }

    boolean successfullyDeleted = permissionsDataService
        .deleteAccessControlEntry(credentialName, actor);

    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }
  }
}
