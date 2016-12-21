package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.jpa.repository.JpaRepository;

import static com.google.common.collect.Lists.newArrayList;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public interface SecretRepository extends JpaRepository<NamedSecret, UUID> {
  NamedSecret findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(String name);
  NamedSecret findOneByUuid(UUID uuid);
  List<NamedSecret> deleteByNameIgnoreCase(String name);
  List<NamedSecret> findAllByNameIgnoreCase(String name);

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
