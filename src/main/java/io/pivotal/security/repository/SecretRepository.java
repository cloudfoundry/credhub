package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import static com.google.common.collect.Lists.newArrayList;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public interface SecretRepository extends JpaRepository<NamedSecret, UUID> {
  NamedSecret findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(String name);
  NamedSecret findOneByUuid(UUID uuid);

  @Transactional
  long deleteByNameIgnoreCase(String name);
  List<NamedSecret> findAllByNameIgnoreCase(String name);
  Long countByEncryptionKeyUuidNot(UUID encryptionKeyUuid);
  Long countByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);
  Slice<NamedSecret> findByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page);

  default List<String> findAllPaths(Boolean findPaths) {
    if (!findPaths) {
      return newArrayList();
    }

    return findAll().stream()
        .map(NamedSecret::getName)
        .flatMap(NamedSecret::fullHierarchyForPath)
        .distinct()
        .sorted()
        .collect(Collectors.toList());
  }
}
