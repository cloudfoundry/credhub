package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
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
public class AccessControlDataService {

  private AccessEntryRepository accessEntryRepository;
  private final CredentialNameDataService credentialNameDataService;

  @Autowired
  public AccessControlDataService(
      AccessEntryRepository accessEntryRepository,
      CredentialNameDataService credentialNameDataService
  ) {
    this.accessEntryRepository = accessEntryRepository;
    this.credentialNameDataService = credentialNameDataService;
  }

  public List<PermissionEntry> getAccessControlList(CredentialName credentialName) {
    return createViewsForAllAcesWithName(credentialName);
  }

  public void saveAccessControlEntries(
      CredentialName credentialName,
      List<PermissionEntry> entries
  ) {
    List<AccessEntryData> existingAccessEntries = accessEntryRepository
        .findAllByCredentialNameUuid(credentialName.getUuid());

    for (PermissionEntry ace : entries) {
      upsertAccessEntryOperations(credentialName, existingAccessEntries, ace.getActor(),
          ace.getAllowedOperations());
    }
  }

  public List<PermissionOperation> getAllowedOperations(String name, String actor) {
    List<PermissionOperation> operations = newArrayList();
    CredentialName credentialName = credentialNameDataService.find(name);
    AccessEntryData accessEntryData = accessEntryRepository.findByCredentialNameAndActor(credentialName, actor);

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
    CredentialName credentialName = credentialNameDataService.find(name);
    return accessEntryRepository.deleteByCredentialNameAndActor(credentialName, actor) > 0;
  }

  public boolean hasReadAclPermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    final AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameAndActor(credentialName, actor);
    return accessEntryData != null && accessEntryData.hasReadAclPermission();
  }

  public boolean hasAclWritePermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    final AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameAndActor(credentialName, actor);
    return accessEntryData != null && accessEntryData.hasWriteAclPermission();
  }

  public boolean hasReadPermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameAndActor(credentialName, actor);
    return accessEntryData != null && accessEntryData.hasReadPermission();
  }

  public boolean hasCredentialWritePermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameAndActor(credentialName, actor);
    return accessEntryData != null && accessEntryData.hasWritePermission();
  }

  public boolean hasCredentialDeletePermission(String actor, String name) {
    CredentialName credentialName = credentialNameDataService.find(name);
    AccessEntryData accessEntryData =
        accessEntryRepository.findByCredentialNameAndActor(credentialName, actor);
    return accessEntryData != null && accessEntryData.hasDeletePermission();
  }

  private void upsertAccessEntryOperations(CredentialName credentialName,
      List<AccessEntryData> accessEntries, String actor, List<PermissionOperation> operations) {
    AccessEntryData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new AccessEntryData(credentialName, actor);
    }

    entry.enableOperations(operations);
    accessEntryRepository.saveAndFlush(entry);
  }

  private PermissionEntry createViewFor(AccessEntryData data) {
    if (data == null ) {
      return null;
    }
    PermissionEntry entry = new PermissionEntry();
    List<PermissionOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<PermissionEntry> createViewsForAllAcesWithName(CredentialName credentialName) {
    return accessEntryRepository.findAllByCredentialNameUuid(credentialName.getUuid())
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
