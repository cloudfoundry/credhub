package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.PermissionRepository;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

@Component
public class PermissionDataService {

  private PermissionRepository permissionRepository;
  private final CredentialDataService credentialDataService;

  @Autowired
  public PermissionDataService(
      PermissionRepository permissionRepository,
      CredentialDataService credentialDataService
  ) {
    this.permissionRepository = permissionRepository;
    this.credentialDataService = credentialDataService;
  }

  public List<PermissionEntry> getPermissions(Credential credential) {
    return createViewsFromPermissionsFor(credential);
  }

  public void savePermissions(
      Credential credential,
      List<PermissionEntry> permissions
  ) {
    List<PermissionData> existingPermissions = permissionRepository
        .findAllByCredentialUuid(credential.getUuid());

    for (PermissionEntry permission : permissions) {
      upsertPermissions(credential, existingPermissions, permission.getActor(),
          permission.getAllowedOperations());
    }
  }

  public List<PermissionOperation> getAllowedOperations(String name, String actor) {
    List<PermissionOperation> operations = newArrayList();
    Credential credential = credentialDataService.find(name);
    PermissionData permissionData = permissionRepository
        .findByCredentialAndActor(credential, actor);

    if (permissionData != null) {
      if (permissionData.hasReadPermission()) {
        operations.add(PermissionOperation.READ);
      }
      if (permissionData.hasWritePermission()) {
        operations.add(PermissionOperation.WRITE);
      }
      if (permissionData.hasDeletePermission()) {
        operations.add(PermissionOperation.DELETE);
      }
      if (permissionData.hasReadAclPermission()) {
        operations.add(PermissionOperation.READ_ACL);
      }
      if (permissionData.hasWriteAclPermission()) {
        operations.add(PermissionOperation.WRITE_ACL);
      }
    }

    return operations;
  }

  public boolean deletePermissions(String name, String actor) {
    Credential credential = credentialDataService.find(name);
    return permissionRepository.deleteByCredentialAndActor(credential, actor) > 0;
  }

  public boolean hasNoDefinedAccessControl(String name) {
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      return false;
    }
    return (permissionRepository.findAllByCredentialUuid(credential.getUuid()).size() == 0);
  }

  public boolean hasPermission(String user, String name, PermissionOperation requiredPermission) {
    Credential credential = credentialDataService.find(name);
    final PermissionData permissionData =
        permissionRepository.findByCredentialAndActor(credential, user);
    return permissionData != null && permissionData.hasPermission(requiredPermission);
  }

  private void upsertPermissions(Credential credential,
                                 List<PermissionData> accessEntries, String actor, List<PermissionOperation> operations) {
    PermissionData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new PermissionData(credential, actor);
    }

    entry.enableOperations(operations);
    permissionRepository.saveAndFlush(entry);
  }

  private PermissionEntry createViewFor(PermissionData data) {
    if (data == null) {
      return null;
    }
    PermissionEntry entry = new PermissionEntry();
    List<PermissionOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<PermissionEntry> createViewsFromPermissionsFor(Credential credential) {
    return permissionRepository.findAllByCredentialUuid(credential.getUuid())
        .stream()
        .map(this::createViewFor)
        .collect(Collectors.toList());
  }

  private PermissionData findAccessEntryForActor(List<PermissionData> accessEntries,
                                                 String actor) {
    Optional<PermissionData> temp = accessEntries.stream()
        .filter(permissionData -> permissionData.getActor().equals(actor))
        .findFirst();
    return temp.orElse(null);
  }
}
