package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException;
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.request.PermissionsV2Request;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.cloudfoundry.credhub.request.PermissionOperation.READ_ACL;
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

  public List<PermissionData> savePermissionsForUser(List<PermissionEntry> permissionEntryList) {

    if (permissionEntryList.size() == 0) {
      return new ArrayList<>();
    }

    UserContext userContext = userContextHolder.getUserContext();
    for (PermissionEntry permissionEntry : permissionEntryList) {
      if (!permissionCheckingService.hasPermission(userContext.getActor(), permissionEntry.getPath(), WRITE_ACL)) {
        throw new EntryNotFoundException("error.credential.invalid_access");
      }
      if (!permissionCheckingService.userAllowedToOperateOnActor(permissionEntry.getActor())) {
        throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
      }
      if (permissionCheckingService.permissionForActorExists(permissionEntry.getActor(), permissionEntry.getPath())) {
        throw new PermissionAlreadyExistsException("error.permission.already_exists");
      }
    }
    return permissionDataService.savePermissionsWithLogging(permissionEntryList);
  }

  public void savePermissions(List<PermissionEntry> permissionEntryList) {
    if (permissionEntryList.size() == 0) {
      return;
    }
    permissionDataService.savePermissions(permissionEntryList);
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

  public PermissionData getPermissions(UUID guid) {
    if (guid == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    if (!permissionCheckingService.hasPermission(userContextHolder.getUserContext().getActor(), guid, READ_ACL)) {
      throw new InvalidPermissionException("error.invalid_permission");
    }

    return permissionDataService.getPermission(guid);
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

  public PermissionData putPermissions(String guid, PermissionsV2Request permissionsRequest) {
    UserContext userContext = userContextHolder.getUserContext();
    UUID permissionUUID = parseUUID(guid);
    checkActorPermissions(permissionUUID, userContext.getActor());

    return permissionDataService.putPermissions(guid, permissionsRequest);
  }

  public PermissionData patchPermissions(String guid, List<PermissionOperation> operations) {
    UserContext userContext = userContextHolder.getUserContext();
    UUID permissionUUID = parseUUID(guid);
    checkActorPermissions(permissionUUID, userContext.getActor());

    return permissionDataService.patchPermissions(guid, operations);
  }

  public PermissionData saveV2Permissions(PermissionsV2Request permissionsRequest) {
    UserContext userContext = userContextHolder.getUserContext();
    if (!permissionCheckingService.hasPermission(userContext.getActor(), permissionsRequest.getPath(), WRITE_ACL)) {
      throw new EntryNotFoundException("error.credential.invalid_access");
    }
    if (!permissionCheckingService.userAllowedToOperateOnActor(permissionsRequest.getActor())) {
      throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
    }
    return permissionDataService.saveV2Permissions(permissionsRequest);
  }

  private void checkActorPermissions(UUID permissionUUID, String actor) {
    if (!permissionCheckingService.hasPermission(actor, permissionUUID, WRITE_ACL)) {
      throw new EntryNotFoundException("error.permission.does_not_exist");
    }
    if (!permissionCheckingService.userAllowedToOperateOnActor(permissionUUID)) {
      throw new InvalidPermissionOperationException("error.permission.invalid_update_operation");
    }
  }

  private UUID parseUUID(String guid) {
    UUID permissionUUID;
    try{
      permissionUUID = UUID.fromString(guid);
    }catch (IllegalArgumentException e){
      throw new PermissionDoesNotExistException("error.permission.does_not_exist");
    }
    return permissionUUID;
  }
}
