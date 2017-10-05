package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialNameDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionCheckingService;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class PermissionsHandler {

  private final PermissionService permissionService;
  private final PermissionCheckingService permissionCheckingService;
  private final CredentialNameDataService credentialNameDataService;

  @Autowired
  PermissionsHandler(
      PermissionService permissionService,
      PermissionCheckingService permissionCheckingService,
      CredentialNameDataService credentialNameDataService
  ) {
    this.permissionService = permissionService;
    this.permissionCheckingService = permissionCheckingService;
    this.credentialNameDataService = credentialNameDataService;
  }

  public PermissionsView getPermissions(String name, UserContext userContext) {
    final CredentialName credentialName = credentialNameDataService.findOrThrow(name);

    return new PermissionsView(
        credentialName.getName(),
        permissionService.getAccessControlList(userContext, credentialName)
    );
  }

  public PermissionsView setPermissions(
      String name,
      UserContext userContext,
      List<PermissionEntry> permissionEntryList
  ) {
    final CredentialName credentialName = credentialNameDataService.find(name);

    // We need to verify that the credential exists in case ACL enforcement is off
    if (credentialName == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    for (PermissionEntry permissionEntry : permissionEntryList) {
      if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, permissionEntry.getActor())) {
        throw new InvalidAclOperationException("error.acl.invalid_update_operation");
      }
    }

    permissionService.saveAccessControlEntries(userContext, credentialName, permissionEntryList);

    return new PermissionsView(
        credentialName.getName(),
        permissionService.getAccessControlList(userContext, credentialName)
    );
  }

  public void deletePermissionEntry(UserContext userContext,
      String credentialName, String actor) {

    boolean successfullyDeleted = permissionService
        .deleteAccessControlEntry(userContext, credentialName, actor);

    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
  }
}
