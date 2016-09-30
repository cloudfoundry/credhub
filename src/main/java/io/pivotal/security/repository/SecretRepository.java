package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.*;

import static com.google.common.collect.Lists.newArrayList;

public interface SecretRepository extends JpaRepository<NamedSecret, Long> {
  NamedSecret findOneByName(String name);
  NamedSecret findOneByUuid(String uuid);
  List<NamedSecret> findByNameContainingOrderByUpdatedAtDesc(String nameSubstring);
  List<NamedSecret> findByNameStartingWithOrderByUpdatedAtDesc(String nameSubstring);

  @Query("SELECT DISTINCT path FROM NamedSecret WHERE path <> '' ORDER BY path")
  List<String> getAllNamedSecretPaths();

  default List<String> findAllPaths(Boolean findPaths) {
    if (!findPaths) {
      return newArrayList();
    }

    List<String> secretPaths = getAllNamedSecretPaths();
    List<String> allPaths = newArrayList();
    for (int i = 0, ii = secretPaths.size(); i < ii; ++i) {
      String secretPath = secretPaths.get(i);
      if(i < ii - 1 && secretPaths.get(i + 1).startsWith(secretPath)) {
        continue;
      }
      addSubpaths(secretPath, allPaths);
    }
    return allPaths;
  }

  default void addSubpaths(String secretPath, List<String> pathSet) {
    String[] elements = secretPath.split("/");
    StringBuilder currentPath = new StringBuilder();
    for(String element: elements) {
      currentPath.append(element).append('/');
      pathSet.add(currentPath.toString());
    }
  }
}
