package io.pivotal.security.data;

import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSecretImpl;
import io.pivotal.security.repository.SecretRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import static com.google.common.collect.Lists.newArrayList;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class SecretDataService {
  private static final String FIND_MOST_RECENT_BY_SUBSTRING_QUERY =
    "SELECT DISTINCT " +
      "name, " +
      "updated_at " +
    "FROM " +
      "named_secret " +
    "INNER JOIN ( " +
      "SELECT " +
        "UPPER(name) AS inner_name, " +
        "MAX(updated_at) AS inner_updated_at " +
      "FROM " +
        "named_secret " +
      "GROUP BY " +
        "UPPER(name) " +
    ") AS most_recent " +
    "ON " +
      "named_secret.updated_at = most_recent.inner_updated_at " +
    "AND " +
      "UPPER(named_secret.name) = most_recent.inner_name " +
    "WHERE " +
      "UPPER(named_secret.name) LIKE UPPER(?) " +
    "ORDER BY updated_at DESC";

  @Autowired
  public SecretRepository secretRepository;

  @Autowired
  JdbcTemplate jdbcTemplate;

  public NamedSecret save(NamedSecret namedSecret) {
    return secretRepository.saveAndFlush(namedSecret);
  }

  public List<String> findAllPaths() {
    return secretRepository.findAllPaths(true);
  }

  public List<NamedSecret> findMostRecentAsList(String name) {
    NamedSecret foundSecret = findMostRecent(name);
    return foundSecret == null ? newArrayList() : newArrayList(foundSecret);
  }

  public List<NamedSecret> findByUuidAsList(String uuid) {
    NamedSecret foundSecret = findByUuid(uuid);
    return foundSecret == null ? newArrayList() : newArrayList(foundSecret);
  }

  public NamedSecret findMostRecent(String name) {
    return secretRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }

  public NamedSecret findByUuid(String uuid) {
    return secretRepository.findOneByUuid(UUID.fromString(uuid));
  }

  public List<NamedSecret> findContainingName(String name) {
    return findMostRecentLikeSubstring('%' + name + '%');
  }

  public List<NamedSecret> findStartingWithName(String name) {
    if (!name.endsWith("/")) {
      name += '/';
    }
    name += '%';

    return findMostRecentLikeSubstring(name);
  }

  public List<NamedSecret> delete(String name) {
    return secretRepository.deleteByNameIgnoreCase(name);
  }

  public List<NamedSecret> findAllByName(String name) {
    return secretRepository.findAllByNameIgnoreCase(name);
  }

  private List<NamedSecret> findMostRecentLikeSubstring(String substring) {
    secretRepository.flush();

    // The subquery gets us the right name/updated_at pairs, but changes the capitalization of the names.
    return jdbcTemplate.query(
        FIND_MOST_RECENT_BY_SUBSTRING_QUERY,
      new Object[] {substring},
      (rowSet, rowNum) -> {
        NamedSecret secret = new NamedSecretImpl();

        secret.setName(rowSet.getString("name"));
        secret.setUpdatedAt(Instant.ofEpochSecond(rowSet.getLong("updated_at")));

        return secret;
      }
    );
  }
}
