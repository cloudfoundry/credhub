package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.AccessControlListResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

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
    credentialName = addLeadingSlashIfMissing(credentialName);

    permissionService.verifyAclReadPermission(userContext, credentialName);

    List<AccessControlEntry> accessControlList = accessControlDataService.getAccessControlList(credentialName);
    AccessControlListResponse response = new AccessControlListResponse();
    response.setCredentialName(credentialName);
    response.setAccessControlList(accessControlList);

    return response;
  }

  public AccessControlListResponse setAccessControlEntries(AccessEntriesRequest request) {
    String credentialName = addLeadingSlashIfMissing(request.getCredentialName());

    List<AccessControlEntry> accessControlEntryList = accessControlDataService
        .setAccessControlEntries(credentialName, request.getAccessControlEntries());

    AccessControlListResponse response = new AccessControlListResponse();
    response.setCredentialName(credentialName);
    response.setAccessControlList(accessControlEntryList);

    return response;
  }

  public void deleteAccessControlEntries(String credentialName, String actor) {
    accessControlDataService.deleteAccessControlEntries(credentialName, actor);
  }

  private static String addLeadingSlashIfMissing(String name) {
    return StringUtils.prependIfMissing(name, "/");
  }
}
