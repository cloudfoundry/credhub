package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.data.CredentialNameDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.PermissionsView;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AccessControlHandler {
  private final PermissionService permissionService;
  private final AccessControlDataService accessControlDataService;
  private final CredentialNameDataService credentialNameDataService;

  @Autowired
  AccessControlHandler(
      PermissionService permissionService,
      AccessControlDataService accessControlDataService,
      CredentialNameDataService credentialNameDataService
  ) {
    this.permissionService = permissionService;
    this.accessControlDataService = accessControlDataService;
    this.credentialNameDataService = credentialNameDataService;
  }

  public PermissionsView getAccessControlListResponse(UserContext userContext, String name) {
    try {
      final CredentialName credentialName = credentialNameDataService.findOrThrow(name);

      permissionService.verifyAclReadPermission(userContext, name);

      return new PermissionsView(
          credentialName.getName(),
          accessControlDataService.getAccessControlList(credentialName)
      );
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }
  }

  public PermissionsView setAccessControlEntries(UserContext userContext, String name, List<AccessControlEntry> accessControlEntryList) {
    if (!permissionService.hasAclWritePermission(userContext, name)) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    final CredentialName credentialName = credentialNameDataService.find(name);
    accessControlDataService
        .saveAccessControlEntries(credentialName, accessControlEntryList);

    return new PermissionsView(credentialName.getName(), accessControlDataService.getAccessControlList(credentialName));
  }

  public void deleteAccessControlEntry(UserContext userContext, String credentialName, String actor) {
    if (!permissionService.hasAclWritePermission(userContext, credentialName)) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }

    boolean successfullyDeleted = accessControlDataService.deleteAccessControlEntry(credentialName, actor);

    if (!successfullyDeleted) {
      throw new EntryNotFoundException("error.acl.lacks_credential_write");
    }
  }
}
