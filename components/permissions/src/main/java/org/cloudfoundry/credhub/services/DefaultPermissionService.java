package org.cloudfoundry.credhub.services;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.PermissionData;
import org.cloudfoundry.credhub.data.PermissionDataService;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionException;
import org.cloudfoundry.credhub.exceptions.InvalidPermissionOperationException;
import org.cloudfoundry.credhub.exceptions.PermissionAlreadyExistsException;
import org.cloudfoundry.credhub.exceptions.PermissionDoesNotExistException;
import org.cloudfoundry.credhub.requests.PermissionEntry;
import org.cloudfoundry.credhub.requests.PermissionsV2Request;
import org.jetbrains.annotations.NotNull;

@Service
public class DefaultPermissionService implements PermissionService {

  private final PermissionDataService permissionDataService;
  private final PermissionCheckingService permissionCheckingService;
  private final UserContextHolder userContextHolder;

  @Autowired
  public DefaultPermissionService(
    final PermissionDataService permissionDataService,
    final PermissionCheckingService permissionCheckingService,
    final UserContextHolder userContextHolder
  ) {
    super();
    this.permissionDataService = permissionDataService;
    this.permissionCheckingService = permissionCheckingService;
    this.userContextHolder = userContextHolder;
  }

  @NotNull
  @Override
  public List<PermissionOperation> getAllowedOperationsForLogging(@NotNull final String credentialName, @NotNull final String actor) {
    return permissionDataService.getAllowedOperations(credentialName, actor);
  }

  @NotNull
  @Override
  public List<PermissionData> savePermissionsForUser(final List<PermissionEntry> permissionEntryList) {

    if (permissionEntryList.isEmpty()) {
      return new ArrayList<>();
    }

    final UserContext userContext = userContextHolder.getUserContext();
    for (final PermissionEntry permissionEntry : permissionEntryList) {
      if (!permissionCheckingService
        .hasPermission(userContext.getActor(), permissionEntry.getPath(), PermissionOperation.WRITE_ACL)) {
        throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
      }
      if (!permissionCheckingService.userAllowedToOperateOnActor(permissionEntry.getActor())) {
        throw new InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION);
      }
      if (permissionCheckingService.hasPermissions(permissionEntry.getActor(), permissionEntry.getPath(),
        permissionEntry.getAllowedOperations())) {
        throw new PermissionAlreadyExistsException(ErrorMessages.Permissions.ALREADY_EXISTS);
      }
    }
    return permissionDataService.savePermissionsWithLogging(permissionEntryList);
  }

  @Override
  public void savePermissions(final List<PermissionEntry> permissionEntryList) {
    if (permissionEntryList.isEmpty()) {
      return;
    }
    permissionDataService.savePermissions(permissionEntryList);
  }

  @NotNull
  @Override
  public List<PermissionEntry> getPermissions(final CredentialVersion credentialVersion) {
    if (credentialVersion == null) {
      throw new EntryNotFoundException(ErrorMessages.RESOURCE_NOT_FOUND);
    }

    if (!permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), credentialVersion.getName(),
        PermissionOperation.READ_ACL)) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }

    return getPermissions(credentialVersion.getCredential());
  }

  @NotNull
  @Override
  public PermissionData getPermissions(final UUID guid) {
    if (guid == null) {
      throw new EntryNotFoundException(ErrorMessages.RESOURCE_NOT_FOUND);
    }

    if (!permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), guid, PermissionOperation.READ_ACL)) {
      throw new InvalidPermissionException(ErrorMessages.Credential.INVALID_ACCESS);
    }

    return permissionDataService.getPermission(guid);
  }

  @Override
  public boolean deletePermissions(@NotNull final String credentialName, @NotNull final String actor) {
    if (!permissionCheckingService
      .hasPermission(userContextHolder.getUserContext().getActor(), credentialName, PermissionOperation.WRITE_ACL)) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }

    if (!permissionCheckingService.userAllowedToOperateOnActor(actor)) {
      throw new InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION);
    }

    return permissionDataService.deletePermissions(credentialName, actor);
  }

  @NotNull
  @Override
  public PermissionData putPermissions(@NotNull final String guid, @NotNull final PermissionsV2Request permissionsRequest) {
    final UserContext userContext = userContextHolder.getUserContext();
    final UUID permissionUUID = parseUUID(guid);
    checkActorPermissions(permissionUUID, userContext.getActor());

    return permissionDataService.putPermissions(guid, permissionsRequest);
  }

  @NotNull
  @Override
  public PermissionData patchPermissions(@NotNull final String guid, final List<PermissionOperation> operations) {
    final UserContext userContext = userContextHolder.getUserContext();
    final UUID permissionUUID = parseUUID(guid);
    checkActorPermissions(permissionUUID, userContext.getActor());

    return permissionDataService.patchPermissions(guid, operations);
  }

  @NotNull
  @Override
  public PermissionData saveV2Permissions(final PermissionsV2Request permissionsRequest) {
    final UserContext userContext = userContextHolder.getUserContext();
    if (!permissionCheckingService
      .hasPermission(userContext.getActor(), permissionsRequest.getPath(), PermissionOperation.WRITE_ACL)) {
      throw new EntryNotFoundException(ErrorMessages.Credential.INVALID_ACCESS);
    }
    if (!permissionCheckingService.userAllowedToOperateOnActor(permissionsRequest.getActor())) {
      throw new InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION);
    }
    return permissionDataService.saveV2Permissions(permissionsRequest);
  }

  @NotNull
  @Override
  public PermissionData deletePermissions(@NotNull final String guid) {
    final UserContext userContext = userContextHolder.getUserContext();
    final UUID permissionUUID = parseUUID(guid);
    checkActorPermissions(permissionUUID, userContext.getActor());
    return permissionDataService.deletePermissions(permissionUUID);
  }

  @Override
  public PermissionData findByPathAndActor(@NotNull final String path, @NotNull final String actor) {
    final UserContext userContext = userContextHolder.getUserContext();
    if (!permissionCheckingService.hasPermission(userContext.getActor(), path, PermissionOperation.READ_ACL)) {
      throw new EntryNotFoundException(ErrorMessages.Permissions.INVALID_ACCESS);
    }
    return permissionDataService.findByPathAndActor(path, actor);
  }

  private void checkActorPermissions(final UUID permissionUUID, final String actor) {
    if (!permissionCheckingService.hasPermission(actor, permissionUUID, PermissionOperation.WRITE_ACL)) {
      throw new EntryNotFoundException(ErrorMessages.Permissions.DOES_NOT_EXIST);
    }
    if (!permissionCheckingService.userAllowedToOperateOnActor(permissionUUID)) {
      throw new InvalidPermissionOperationException(ErrorMessages.Permissions.INVALID_UPDATE_OPERATION);
    }
  }

  private UUID parseUUID(final String guid) {
    final UUID permissionUUID;
    try {
      permissionUUID = UUID.fromString(guid);
    } catch (final IllegalArgumentException e) {
      throw new PermissionDoesNotExistException(ErrorMessages.Permissions.DOES_NOT_EXIST);
    }
    return permissionUUID;
  }

  private List<PermissionEntry> getPermissions(final Credential credential) {
    return permissionDataService.getPermissions(credential);
  }
}
