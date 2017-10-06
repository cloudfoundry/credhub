package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.PermissionOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

@Component
public class PermissionsDataService {

  private AccessEntryRepository accessEntryRepository;
  private final CredentialDataService credentialDataService;

  @Autowired
  public PermissionsDataService(
      AccessEntryRepository accessEntryRepository,
      CredentialDataService credentialDataService
  ) {
    this.accessEntryRepository = accessEntryRepository;
    this.credentialDataService = credentialDataService;
  }

  public List<PermissionEntry> getAccessControlList(Credential credential) {
    return createViewsForAllAcesWithName(credential);
  }

  public void saveAccessControlEntries(
      Credential credential,
      List<PermissionEntry> entries
  ) {
    List<AccessEntryData> existingAccessEntries = accessEntryRepository
        .findAllByCredentialUuid(credential.getUuid());

    for (PermissionEntry ace : entries) {
      upsertAccessEntryOperations(credential, existingAccessEntries, ace.getActor(),
          ace.getAllowedOperations());
    }
  }

  public List<PermissionOperation> getAllowedOperations(String name, String actor) {
    List<PermissionOperation> operations = newArrayList();
    Credential credential = credentialDataService.find(name);
    AccessEntryData accessEntryData = accessEntryRepository
        .findByCredentialAndActor(credential, actor);

    if (accessEntryData != null) {
      if (accessEntryData.hasReadPermission()) {
        operations.add(PermissionOperation.READ);
      }
      if (accessEntryData.hasWritePermission()) {
        operations.add(PermissionOperation.WRITE);
      }
      if (accessEntryData.hasDeletePermission()) {
        operations.add(PermissionOperation.DELETE);
      }
      if (accessEntryData.hasReadAclPermission()) {
        operations.add(PermissionOperation.READ_ACL);
      }
      if (accessEntryData.hasWriteAclPermission()) {
        operations.add(PermissionOperation.WRITE_ACL);
      }
    }

    return operations;
  }

  public boolean deleteAccessControlEntry(String name, String actor) {
    Credential credential = credentialDataService.find(name);
    return accessEntryRepository.deleteByCredentialAndActor(credential, actor) > 0;
  }

  public boolean hasNoDefinedAccessControl(String name) {
    Credential credential = credentialDataService.find(name);
    if (credential == null) {
      return false;
    }
    return (accessEntryRepository.findAllByCredentialUuid(credential.getUuid()).size() == 0);
  }

  public boolean hasPermission(String user, String name, PermissionOperation requiredPermission) {
    Credential credential = credentialDataService.find(name);
    final AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialAndActor(credential, user);
    return accessEntryData != null && accessEntryData.hasPermission(requiredPermission);
  }

  private void upsertAccessEntryOperations(Credential credential,
      List<AccessEntryData> accessEntries, String actor, List<PermissionOperation> operations) {
    AccessEntryData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new AccessEntryData(credential, actor);
    }

    entry.enableOperations(operations);
    accessEntryRepository.saveAndFlush(entry);
  }

  private PermissionEntry createViewFor(AccessEntryData data) {
    if (data == null) {
      return null;
    }
    PermissionEntry entry = new PermissionEntry();
    List<PermissionOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<PermissionEntry> createViewsForAllAcesWithName(Credential credential) {
    return accessEntryRepository.findAllByCredentialUuid(credential.getUuid())
        .stream()
        .map(this::createViewFor)
        .collect(Collectors.toList());
  }

  private AccessEntryData findAccessEntryForActor(List<AccessEntryData> accessEntries,
      String actor) {
    Optional<AccessEntryData> temp = accessEntries.stream()
        .filter(accessEntryData -> accessEntryData.getActor().equals(actor))
        .findFirst();
    return temp.orElse(null);
  }
}
