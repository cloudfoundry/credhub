package io.pivotal.security.service.permissions;

import io.pivotal.security.data.AccessControlDataService;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessEntriesRequest;
import io.pivotal.security.view.AccessControlListResponse;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccessControlViewService {
  private final AccessControlDataService accessControlDataService;

  @Autowired
  AccessControlViewService(AccessControlDataService accessControlDataService) {
    this.accessControlDataService = accessControlDataService;
  }

  public AccessControlListResponse getAccessControlListResponse(String credentialName) {
    credentialName = addLeadingSlashIfMissing(credentialName);

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

  private static String addLeadingSlashIfMissing(String name) {
    return StringUtils.prependIfMissing(name, "/");
  }
}
