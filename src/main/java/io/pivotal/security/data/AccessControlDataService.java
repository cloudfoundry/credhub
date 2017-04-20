package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class AccessControlDataService {

  private AccessEntryRepository accessEntryRepository;
  private CredentialNameRepository credentialNameRepository;

  @Autowired
  public AccessControlDataService(
      AccessEntryRepository accessEntryRepository,
      CredentialNameRepository credentialNameRepository
  ) {
    this.accessEntryRepository = accessEntryRepository;
    this.credentialNameRepository = credentialNameRepository;
  }

  public List<AccessControlEntry> getAccessControlList(String name) {
    CredentialName credentialName = findCredentialName(name);
    return createViewsForAllAcesWithName(credentialName);
  }

  public List<AccessControlEntry> setAccessControlEntries(
      String name,
      List<AccessControlEntry> entries
  ) {
    CredentialName credentialName = findCredentialName(name);

    List<AccessEntryData> existingAccessEntries = accessEntryRepository
        .findAllByCredentialNameUuid(credentialName.getUuid());

    for (AccessControlEntry ace : entries) {
      upsertAccessEntryOperations(credentialName, existingAccessEntries, ace.getActor(),
          ace.getAllowedOperations());
    }

    return createViewsForAllAcesWithName(credentialName);
  }

  public void deleteAccessControlEntries(String name, String actor) {
    final CredentialName credentialName = findCredentialName(name);
    accessEntryRepository.deleteByCredentialNameUuidAndActor(credentialName.getUuid(), actor);
  }

  public boolean hasReadAclPermission(String actor, String name) {
    CredentialName credentialName = credentialNameRepository.findOneByNameIgnoreCase(name);

    if (credentialName == null) {
      return false;
    }

    UUID uuid = credentialName.getUuid();
    AccessEntryData accessEntryData = accessEntryRepository
        .findByCredentialNameUuidAndActor(uuid, actor);

    if (accessEntryData == null) {
      return false;
    } else {
      return (accessEntryData.hasReadAclPermission());
    }
  }

  public boolean hasReadPermission(String actor, String name) {
    CredentialName credentialName = credentialNameRepository.findOneByNameIgnoreCase(name);

    if (credentialName == null) {
      return false;
    }

    UUID uuid = credentialName.getUuid();
    AccessEntryData accessEntryData = accessEntryRepository
        .findByCredentialNameUuidAndActor(uuid, actor);

    if (accessEntryData == null) {
      return false;
    } else {
      return (accessEntryData.hasReadPermission());
    }
  }

  private void upsertAccessEntryOperations(CredentialName credentialName,
      List<AccessEntryData> accessEntries, String actor, List<AccessControlOperation> operations) {
    AccessEntryData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new AccessEntryData(credentialName, actor);
    }

    entry.enableOperations(operations);
    accessEntryRepository.saveAndFlush(entry);
  }

  private CredentialName findCredentialName(String name) {
    name = StringUtils.prependIfMissing(name, "/");
    final CredentialName credentialName = credentialNameRepository
        .findOneByNameIgnoreCase(name);

    if (credentialName == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }
    return credentialName;
  }

  private AccessControlEntry createViewFor(AccessEntryData data) {
    AccessControlEntry entry = new AccessControlEntry();
    List<AccessControlOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<AccessControlEntry> createViewsForAllAcesWithName(CredentialName credentialName) {
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
