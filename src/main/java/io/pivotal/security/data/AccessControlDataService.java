package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class AccessControlDataService {

  private AccessEntryRepository accessEntryRepository;
  private SecretDataService secretDataService;

  @Autowired
  public AccessControlDataService(AccessEntryRepository accessEntryRepository,
                                  SecretDataService secretDataService) {
    this.accessEntryRepository = accessEntryRepository;
    this.secretDataService = secretDataService;
  }

  public AccessControlListResponse setAccessControlEntry(AccessEntryRequest request) {
    SecretName secretName = findSecretName(request);

    List<AccessEntryData> existingAccessEntries = accessEntryRepository.findAllByCredentialNameUuid(secretName.getUuid());

    for (AccessControlEntry ace : request.getAccessControlEntries()) {
      upsertAccessEntryOperations(secretName, existingAccessEntries, ace.getActor(), ace.getAllowedOperations());
    }

    List<AccessControlEntry> responseAces = createViewsForAllAcesWithName(secretName);

    return new AccessControlListResponse(secretName.getName(), responseAces);
  }

  public AccessControlListResponse getAccessControlList(String credentialName) {
    SecretName secretName = secretDataService.findSecretName(credentialName);
    List<AccessControlEntry> responseAces = null;

    if (secretName != null) {
      responseAces = createViewsForAllAcesWithName(secretName);
    }

    if (responseAces == null || secretName == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }

    return new AccessControlListResponse(secretName.getName(), responseAces);
  }

  public void deleteAccessControlEntry(String credentialName, String actor) {
    int rows = 0;
    final SecretName secretName = secretDataService.findSecretName(credentialName);
    if (secretName != null) {
      rows = accessEntryRepository.deleteByCredentialNameUuidAndActor(secretName.getUuid(), actor);
    }

    if (secretName == null || rows == 0) {
      throw new EntryNotFoundException("error.acl.not_found");
    }
  }

  private void upsertAccessEntryOperations(SecretName secretName, List<AccessEntryData> accessEntries, String actor, List<AccessControlOperation> operations) {
    AccessEntryData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new AccessEntryData(secretName, actor);
    }

    entry.enableOperations(operations);
    accessEntryRepository.saveAndFlush(entry);
  }

  private SecretName findSecretName(AccessEntryRequest request) {
    final SecretName secretName = secretDataService.findSecretName(request.getCredentialName());

    if (secretName == null) {
      throw new EntryNotFoundException("error.resource_not_found");
    }
    return secretName;
  }

  private AccessControlEntry createViewFor(AccessEntryData data) {
    AccessControlEntry entry = new AccessControlEntry();
    List<AccessControlOperation> operations = data.generateAccessControlOperations();
    entry.setAllowedOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<AccessControlEntry> createViewsForAllAcesWithName(SecretName secretName) {
    return accessEntryRepository.findAllByCredentialNameUuid(secretName.getUuid())
        .stream()
        .map(this::createViewFor)
        .collect(Collectors.toList());
  }

  public AccessEntryData findAccessEntryForActor(List<AccessEntryData> accessEntries, String actor) {
    Optional<AccessEntryData> temp = accessEntries.stream()
        .filter(accessEntryData -> accessEntryData.getActor().equals(actor))
        .findFirst();
    return temp.isPresent() ? temp.get() : null;
  }
}
