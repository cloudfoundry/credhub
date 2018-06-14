package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

import static java.util.Arrays.asList;
import static org.cloudfoundry.credhub.request.PermissionOperation.DELETE;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ;
import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE;
import static org.cloudfoundry.credhub.request.PermissionOperation.WRITE_ACL;

@Service
public class PermissionService {

  private PermissionDataService permissionDataService;
  private PermissionCheckingService permissionCheckingService;
  private UserContextHolder userContextHolder;

  @Autowired
  public PermissionService(PermissionDataService permissionDataService,
                           PermissionCheckingService permissionCheckingService,
                           UserContextHolder userContextHolder) {
    this.permissionDataService = permissionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  public List<PermissionOperation> getAllowedOperationsForLogging(String credentialName, String actor) {
    return permissionDataService.getAllowedOperations(credentialName, actor);
  }

  public void savePermissionsForUser(CredentialVersion credentialVersion,
                                     List<PermissionEntry> permissionEntryList,
                                     boolean isNewCredential) {
    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    for (PermissionEntry permissionEntry : permissionEntryList) {
      if (!permissionCheckingService.userAllowedToOperateOnActor(permissionEntry.getActor())) {
        throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
      }
    }

    UserContext userContext = userContextHolder.getUserContext();

    if (isNewCredential) {
      final PermissionEntry permissionEntry = new PermissionEntry(userContext.getActor(), asList(READ, WRITE, DELETE, WRITE_ACL, READ_ACL));
      permissionEntryList.add(permissionEntry);
    }

    if (permissionEntryList.size() == 0) {
      return;
    }
    if (!permissionCheckingService.hasPermission(userContext.getActor(), credentialVersion.getName(), WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    permissionDataService.savePermissions(credentialVersion.getCredential(), permissionEntryList);
  }

  public void savePermissions(CredentialVersion credentialVersion, List<PermissionEntry> permissionEntryList) {
    if (permissionEntryList.size() == 0) {
      return;
    }
    if (credentialVersion == null) {
      return;
    }
    permissionDataService.savePermissions(credentialVersion.getCredential(), permissionEntryList);
  }

  public List<PermissionEntry> getPermissions(CredentialVersion credentialVersion) {
    if (credentialVersion == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), credentialVersion.getName(), READ_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    return getPermissions(credentialVersion.getCredential());
  }

  public boolean deletePermissions(String credentialName, String actor) {
    if (!permissionCheckingService
        .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }

    if (!permissionCheckingService.userAllowedToOperateOnActor(actor)) {
      throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
    }

    return permissionDataService.deletePermissions(credentialName, actor);
  }

  private List<PermissionEntry> getPermissions(Credential credential) {
    return permissionDataService.getPermissions(credential);
  }
}
