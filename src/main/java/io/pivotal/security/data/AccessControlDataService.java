package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.view.AccessControlListResponse;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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

  public AccessControlListResponse getAccessControlListResponse (String name){
    CredentialName credentialName = findCredentialName(name);
    return new AccessControlListResponse(credentialName.getName(), createViewsForAllAcesWithName(credentialName));
  }

  public List<AccessControlEntry> getAccessControlList(String name) {
    CredentialName credentialName = findCredentialName(name);
    return createViewsForAllAcesWithName(credentialName);
  }

  public void setAccessControlEntries(
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
  }

  public AccessControlEntry deleteAccessControlEntries(String actor, String name) {
    AccessEntryData entry = getPermissionIfCredentialExists(actor, name);
    if (entry != null) {
      accessEntryRepository.delete(entry);
      return createViewFor(entry);
    }
    return null;
  }

  private AccessEntryData getPermissionIfCredentialExists(String actor, String credential){
    CredentialName credentialName = findCredentialName(credential);
    return getPermissionForCredential(actor, credentialName);

  }

  private AccessEntryData getPermissionForCredential(String actor, CredentialName credentialName){
   UUID uuid = credentialName.getUuid();
   return accessEntryRepository.findByCredentialNameUuidAndActor(uuid, actor);
  }

  private AccessEntryData getActorCredentialPermission(String actor, String credential){
    CredentialName credentialName = credentialNameRepository.findCredentialName(credential);
    if (credentialName != null) {
      return getPermissionForCredential(actor, credentialName);
    }
    else {
      return null;
    }
  }

  public boolean hasReadAclPermission(String actor, String name) {
    AccessEntryData accessEntryData = getActorCredentialPermission(actor, name);
    return accessEntryData != null && accessEntryData.hasReadAclPermission();
  }

  public boolean hasReadPermission(String actor, String name) {
    AccessEntryData accessEntryData = getActorCredentialPermission(actor, name);
    return accessEntryData != null && accessEntryData.hasReadPermission();
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
    final CredentialName credentialName = credentialNameRepository.findCredentialName(name);

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
