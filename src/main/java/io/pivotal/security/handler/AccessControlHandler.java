package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.PermissionException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccessControlHandler {
  private final PermissionService permissionService;
  private final AccessControlDataService accessControlDataService;

  @Autowired
  AccessControlHandler(
      PermissionService permissionService,
      AccessControlDataService accessControlDataService
  ) {
    this.permissionService = permissionService;
    this.accessControlDataService = accessControlDataService;
  }

  public AccessControlListResponse getAccessControlListResponse(UserContext userContext, String credentialName) {
    AccessControlListResponse response = null;

    try {
      permissionService.verifyAclReadPermission(userContext, credentialName);
      response = accessControlDataService.getAccessControlListResponse(credentialName);
    } catch (PermissionException pe){
      // lack of permissions should be indistinguishable from not found.
      throw new EntryNotFoundException("error.resource_not_found");
    }

    return response;
  }

  public AccessControlListResponse setAccessControlEntries(AccessEntriesRequest request) {
    accessControlDataService
        .setAccessControlEntries(request.getCredentialName(), request.getAccessControlEntries());

    return accessControlDataService.getAccessControlListResponse(request.getCredentialName());
  }

  public AccessControlEntry deleteAccessControlEntries(String actor, String credentialName) {
    return accessControlDataService.deleteAccessControlEntries(actor, credentialName);
  }

}
