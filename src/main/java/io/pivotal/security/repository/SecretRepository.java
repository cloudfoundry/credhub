package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;

public interface SecretRepository extends JpaRepository<NamedSecret, Long> {
  NamedSecret findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(String name);
  NamedSecret findOneByUuid(String uuid);
  List<NamedSecret> findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(String nameSubstring);
  List<NamedSecret> findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(String nameSubstring);

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
