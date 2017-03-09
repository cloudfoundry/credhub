package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import io.pivotal.security.request.AccessEntryRequest;
import io.pivotal.security.view.AccessControlListResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class AccessControlDataService {

  private AccessEntryRepository accessEntryRepository;
  private SecretNameRepository secretNameRepository;

  @Autowired
  public AccessControlDataService(AccessEntryRepository accessEntryRepository,
                                  SecretNameRepository secretNameRepository) {
    this.accessEntryRepository = accessEntryRepository;
    this.secretNameRepository = secretNameRepository;
  }

  public AccessControlListResponse setAccessControlEntry(AccessEntryRequest request) {
    SecretName secretName = secretNameRepository.findOneByNameIgnoreCase(request.getCredentialName());
    List<AccessEntryData> accessEntries = accessEntryRepository.findAllByCredentialNameUuid(secretName.getUuid());

    for (AccessControlEntry ace : request.getAccessControlEntries()) {
      Optional<AccessEntryData> accessEntry = accessEntries.stream()
        .filter((accessEntryData -> accessEntryData.getActor().equals(ace.getActor())))
        .findFirst();

      if (accessEntry.isPresent()) {
        for (AccessControlOperation operation : ace.getOperations()) {
          switch (operation) {
            case READ:
              accessEntry.get().setReadPermission(true);
              break;
            case WRITE:
              accessEntry.get().setWritePermission(true);
              break;
          }
        }
        accessEntryRepository.saveAndFlush(accessEntry.get());
      } else {
        List<AccessControlOperation> operations = ace.getOperations();
        accessEntryRepository.saveAndFlush(new AccessEntryData(secretName,
          ace.getActor(),
          operations.contains(AccessControlOperation.READ),
          operations.contains(AccessControlOperation.WRITE)
        ));
      }
    }

    List<AccessControlEntry> responseAces = transformAllAccessEntries(secretName);

    return new AccessControlListResponse(request.getCredentialName(), responseAces);
  }

  public AccessControlListResponse getAccessControlList(String credentialName) {
    SecretName secretName = secretNameRepository.findOneByNameIgnoreCase(credentialName);
    List<AccessControlEntry> responseAces = null;

    if (secretName != null) {
      responseAces = transformAllAccessEntries(secretName);
    }

    if (responseAces == null || secretName == null){
      throw new EntryNotFoundException("error.resource_not_found");
    }

    return new AccessControlListResponse(credentialName, responseAces);
  }

  public void deleteAccessControlEntry(String credentialName, String actor) {
    int rows = 0;
    final SecretName secretName = secretNameRepository.findOneByNameIgnoreCase(credentialName);
    if (secretName != null) {
      rows = accessEntryRepository.deleteByCredentialNameUuidAndActor(secretName.getUuid(), actor);
    }

    if (secretName == null || rows == 0){
      throw new EntryNotFoundException("error.acl.not_found");
    }
  }

  private AccessControlEntry transformData(AccessEntryData data) {
    AccessControlEntry entry = new AccessControlEntry();
    List<AccessControlOperation> operations = new ArrayList<>();
    if (data.getReadPermission()) {
      operations.add(AccessControlOperation.READ);
    }
    if (data.getWritePermission()) {
      operations.add(AccessControlOperation.WRITE);
    }
    entry.setOperations(operations);
    entry.setActor(data.getActor());
    return entry;
  }

  private List<AccessControlEntry> transformAllAccessEntries(SecretName secretName) {
    return accessEntryRepository.findAllByCredentialNameUuid(secretName.getUuid())
      .stream().map(this::transformData).collect(Collectors.toList());
  }
}
