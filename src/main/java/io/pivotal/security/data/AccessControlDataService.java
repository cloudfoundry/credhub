package io.pivotal.security.data;

import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.repository.AccessEntryRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.AccessControlOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class AccessControlDataService {

  private AccessEntryRepository accessEntryRepository;
  private SecretDataService secretDataService;
  private final JdbcTemplate jdbcTemplate;

  @Autowired
  public AccessControlDataService(
      AccessEntryRepository accessEntryRepository,
      SecretDataService secretDataService,
      JdbcTemplate jdbcTemplate
  ) {
    this.accessEntryRepository = accessEntryRepository;
    this.secretDataService = secretDataService;
    this.jdbcTemplate = jdbcTemplate;
  }

  public List<AccessControlEntry> getAccessControlList(String credentialName) {
    SecretName secretName = findSecretName(credentialName);
    return createViewsForAllAcesWithName(secretName);
  }

  public List<AccessControlEntry> setAccessControlEntries(
      String credentialName,
      List<AccessControlEntry> entries
  ) {
    SecretName secretName = findSecretName(credentialName);

    List<AccessEntryData> existingAccessEntries = accessEntryRepository
        .findAllByCredentialNameUuid(secretName.getUuid());

    for (AccessControlEntry ace : entries) {
      upsertAccessEntryOperations(secretName, existingAccessEntries, ace.getActor(),
          ace.getAllowedOperations());
    }

    return createViewsForAllAcesWithName(secretName);
  }

  public void deleteAccessControlEntries(String credentialName, String actor) {
    final SecretName secretName = findSecretName(credentialName);
    accessEntryRepository.deleteByCredentialNameUuidAndActor(secretName.getUuid(), actor);
  }

  public boolean hasReadAclPermission(String actor, String credentialName) {
    final Integer count = jdbcTemplate.queryForObject(
        "select count(1) from access_entry " +
            "where secret_name_uuid = (" +
              "select uuid from secret_name where lower(name) = lower(?)" +
            ") and actor = ? and read_acl_permission = true",
        new Object[]{credentialName, actor},
        Integer.class
    );
    return count > 0;
  }

  private void upsertAccessEntryOperations(SecretName secretName,
      List<AccessEntryData> accessEntries, String actor, List<AccessControlOperation> operations) {
    AccessEntryData entry = findAccessEntryForActor(accessEntries, actor);

    if (entry == null) {
      entry = new AccessEntryData(secretName, actor);
    }

    entry.enableOperations(operations);
    accessEntryRepository.saveAndFlush(entry);
  }

  private SecretName findSecretName(String credentialName) {
    final SecretName secretName = secretDataService.findSecretName(credentialName);

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

  private AccessEntryData findAccessEntryForActor(List<AccessEntryData> accessEntries,
      String actor) {
    Optional<AccessEntryData> temp = accessEntries.stream()
        .filter(accessEntryData -> accessEntryData.getActor().equals(actor))
        .findFirst();
    return temp.orElse(null);
  }
}
