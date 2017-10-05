package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.PermissionsDataService;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidAclOperationException;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

import static io.pivotal.security.request.PermissionOperation.READ_ACL;
import static io.pivotal.security.request.PermissionOperation.WRITE_ACL;

@Service
public class PermissionService {

  private PermissionsDataService permissionsDataService;
  private PermissionCheckingService permissionCheckingService;

  @Value("${security.authorization.acls.enabled}")
  private boolean enforcePermissions;

  @Autowired
  public PermissionService(PermissionsDataService permissionsDataService, PermissionCheckingService permissionCheckingService) {
    this.permissionsDataService = permissionsDataService;
    this.permissionCheckingService = permissionCheckingService;
  }

  public List<PermissionOperation> getAllowedOperationsForLogging(String credentialName, String actor) {
    return permissionsDataService.getAllowedOperations(credentialName, actor);
  }

  public void saveAccessControlEntries(UserContext userContext, CredentialName credentialName, List<PermissionEntry> permissionEntryList) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName.getName(), WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    permissionsDataService.saveAccessControlEntries(credentialName, permissionEntryList);
  }

  public List<PermissionEntry> getAccessControlList(UserContext userContext, CredentialName credentialName) {
    if (!permissionCheckingService.hasPermission(userContext.getAclUser(), credentialName.getName(), READ_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return permissionsDataService.getAccessControlList(credentialName);
  }

  public boolean deleteAccessControlEntry(UserContext userContext, String credentialName, String actor) {
    if (!permissionCheckingService
        .hasPermission(userContext.getAclUser(), credentialName, WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!permissionCheckingService.userAllowedToOperateOnActor(userContext, actor)) {
      throw new InvalidAclOperationException("error.acl.invalid_update_operation");
    }

    return permissionsDataService.deleteAccessControlEntry(credentialName, actor);
  }
}
