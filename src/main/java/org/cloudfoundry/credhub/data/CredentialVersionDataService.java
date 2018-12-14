package org.cloudfoundry.credhub.data;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.exceptions.MaximumSizeException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.cloudfoundry.credhub.view.FindCertificateResult;
import org.cloudfoundry.credhub.view.FindCredentialResult;

import static com.google.common.collect.Lists.newArrayList;

@SuppressWarnings("PMD.TooManyMethods")
@Service
public class CredentialVersionDataService {

  private final CredentialVersionRepository credentialVersionRepository;
  private final CredentialDataService credentialDataService;
  private final JdbcTemplate jdbcTemplate;
  private final CredentialFactory credentialFactory;
  private final PermissionDataService permissionDataService;
  private final UserContextHolder userContextHolder;
  private final CertificateVersionDataService certificateVersionDataService;

  @Value("${security.authorization.acls.enabled}")
  private boolean enforcePermissions;

  @Autowired
  protected CredentialVersionDataService(
    final CredentialVersionRepository credentialVersionRepository,
    final PermissionDataService permissionDataService,
    final CredentialDataService credentialDataService,
    final JdbcTemplate jdbcTemplate,
    final CredentialFactory credentialFactory,
    final UserContextHolder userContextHolder,
    final CertificateVersionDataService certificateVersionDataService
  ) {
    super();
    this.credentialVersionRepository = credentialVersionRepository;
    this.permissionDataService = permissionDataService;
    this.credentialDataService = credentialDataService;
    this.jdbcTemplate = jdbcTemplate;
    this.credentialFactory = credentialFactory;
    this.userContextHolder = userContextHolder;
    this.certificateVersionDataService = certificateVersionDataService;
  }

  public <Z extends CredentialVersion> Z save(final Z credentialVersion) {
    return (Z) credentialVersion.save(this);
  }

  public <Z extends CredentialVersion> Z save(final CredentialVersionData credentialVersionData) {
    final Credential credential = credentialVersionData.getCredential();

    if (credential.getUuid() == null) {
      credentialVersionData.setCredential(credentialDataService.save(credential));
    } else {
      final CredentialVersion existingCredentialVersion = findMostRecent(credential.getName());
      if (existingCredentialVersion != null && !existingCredentialVersion.getCredentialType()
        .equals(credentialVersionData.getCredentialType())) {
        throw new ParameterizedValidationException("error.type_mismatch");
      }
    }

    try {
      return (Z) credentialFactory
        .makeCredentialFromEntity(credentialVersionRepository.saveAndFlush(credentialVersionData));
    } catch (final DataIntegrityViolationException e) {
      throw new MaximumSizeException(e.getMessage());
    }
  }

  public CredentialVersion findMostRecent(final String name) {
    final Credential credential = credentialDataService.find(name);

    if (credential == null) {
      return null;
    } else {
      return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
        .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid()));
    }
  }

  public CredentialVersion findByUuid(final String uuid) {
    return credentialFactory
      .makeCredentialFromEntity(credentialVersionRepository.findOneByUuid(UUID.fromString(uuid)));
  }

  public List<String> findAllCertificateCredentialsByCaName(final String caName) {
    final String query = "select distinct credential.name from "
      + "credential, credential_version, certificate_credential "
      + "where credential.uuid=credential_version.credential_uuid "
      + "and credential_version.uuid=certificate_credential.uuid "
      + "and lower(certificate_credential.ca_name) "
      + "like lower(?)";
    return jdbcTemplate.queryForList(query, String.class, caName);
  }

  public List<FindCredentialResult> findContainingName(final String name) {
    return findContainingName(name, "");
  }

  public List<FindCredentialResult> findContainingName(final String name, final String expiresWithinDays) {
    if (!"".equals(expiresWithinDays)) {
      return filterPermissions(filterCertificates("%" + name + "%", expiresWithinDays));
    }
    return filterPermissions(findMatchingName("%" + name + "%"));
  }

  public List<FindCredentialResult> findStartingWithPath(final String path) {
    return findStartingWithPath(path, "");
  }

  public List<FindCredentialResult> findStartingWithPath(final String path, final String expiresWithinDays) {

    String adjustedPath = StringUtils.prependIfMissing(path, "/");
    adjustedPath = StringUtils.appendIfMissing(adjustedPath, "/");

    if (!"".equals(expiresWithinDays)) {
      return filterPermissions(filterCertificates(adjustedPath + "%", expiresWithinDays));
    }

    return filterPermissions(findMatchingName(adjustedPath + "%"));
  }

  public boolean delete(final String name) {
    return credentialDataService.delete(name);
  }

  public List<CredentialVersion> findAllByName(final String name) {
    final Credential credential = credentialDataService.find(name);

    return credential != null ? credentialFactory.makeCredentialsFromEntities(
      credentialVersionRepository.findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid()))
      : newArrayList();
  }

  public List<CredentialVersion> findNByName(final String name, final int numberOfVersions) {
    final Credential credential = credentialDataService.find(name);

    if (credential != null) {
      final List<CredentialVersionData> credentialVersionData = credentialVersionRepository
        .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
        .stream()
        .limit(numberOfVersions)
        .collect(Collectors.toList());
      return credentialFactory.makeCredentialsFromEntities(credentialVersionData);
    } else {
      return newArrayList();
    }
  }

  public Map<UUID, Long> countByEncryptionKey() {
    final Map<UUID, Long> map = new HashMap<>();
    jdbcTemplate.query(
      " SELECT count(*), encryption_key_uuid FROM credential_version " +
        "LEFT JOIN encrypted_value ON credential_version.encrypted_value_uuid = encrypted_value.uuid " +
        "GROUP BY encrypted_value.encryption_key_uuid",
      (rowSet, rowNum) -> map.put(UUID.fromString(rowSet.getString("encryption_key_uuid")), rowSet.getLong("count"))
    );
    return map;
  }

  public List<CredentialVersion> findActiveByName(final String name) {
    final Credential credential = credentialDataService.find(name);
    final CredentialVersionData credentialVersionData;
    final List<CredentialVersion> result = newArrayList();
    if (credential != null) {
      credentialVersionData = credentialVersionRepository
        .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid());

      if (credentialVersionData.getCredentialType().equals(CertificateCredentialVersionData.CREDENTIAL_TYPE)) {
        return certificateVersionDataService.findActiveWithTransitional(name);
      }
      result.add(credentialFactory.makeCredentialFromEntity(credentialVersionData));

      return result;
    } else {
      return newArrayList();
    }
  }

  public Long count() {
    return credentialVersionRepository.count();
  }

  public Long countEncryptedWithKeyUuidIn(final Collection<UUID> uuids) {
    return credentialVersionRepository.countByEncryptedCredentialValueEncryptionKeyUuidIn(uuids);
  }

  private List<FindCredentialResult> filterPermissions(final List<FindCredentialResult> unfilteredResult) {
    if (!enforcePermissions) {
      return unfilteredResult;
    }
    final String actor = userContextHolder.getUserContext().getActor();
    return filterCredentials(unfilteredResult, permissionDataService.findAllPathsByActor(actor));
  }

  private List<FindCredentialResult> filterCredentials(final List<FindCredentialResult> unfilteredResult, final Set<String> permissions) {
    if (permissions.contains("/*")) {
      return unfilteredResult;
    }
    if (permissions.isEmpty()) {
      return new ArrayList<>();
    }

    final List<FindCredentialResult> filteredResult = new ArrayList<>();

    for (final FindCredentialResult credentialResult : unfilteredResult) {
      final String credentialName = credentialResult.getName();
      if (permissions.contains(credentialName)) {
        filteredResult.add(credentialResult);
      }

      for (final String credentialPath : tokenizePath(credentialName)) {
        if (permissions.contains(credentialPath)) {
          filteredResult.add(credentialResult);
          break;
        }
      }
    }
    return filteredResult;
  }

  private List<FindCredentialResult> filterCertificates(final String path, final String expiresWithinDays) {
    final Timestamp expiresTimestamp = Timestamp.from(Instant.now().plus(Duration.ofDays(Long.parseLong(expiresWithinDays))));

    final String query = "select name.name, credential_version.version_created_at, "
      + "certificate_credential.expiry_date from ("
      + "   select "
      + "   max(version_created_at) as version_created_at,"
      + "     credential_uuid, uuid"
      + "   from credential_version group by credential_uuid, uuid"
      + " ) as credential_version inner join ("
      + "   select * from credential"
      + "     where lower(name) like lower(?)"
      + " ) as name"
      + " on credential_version.credential_uuid = name.uuid"
      + " inner join ( select * from certificate_credential"
      + "   where expiry_date <= ?"
      + " ) as certificate_credential "
      + " on credential_version.uuid = certificate_credential.uuid"
      + " order by version_created_at desc";

    final List<FindCredentialResult> certificateResults = jdbcTemplate.query(query,
      new Object[]{path, expiresTimestamp},
      (rowSet, rowNum) -> {
        final Instant versionCreatedAt = Instant
          .ofEpochMilli(rowSet.getLong("version_created_at"));
        final String name = rowSet.getString("name");
        final Instant expiryDate = rowSet.getTimestamp("expiry_date").toInstant();
        return new FindCertificateResult(versionCreatedAt, name, expiryDate);
      }
    );
    return certificateResults;
  }

  private List<String> tokenizePath(final String credentialName) {
    final List<String> result = new ArrayList<>();
    String subPath;

    for (int i = 1; i < credentialName.length(); i++) {
      if (credentialName.charAt(i) == '/') {
        subPath = credentialName.substring(0, i) + "/*";
        result.add(subPath);
      }
    }

    return result;
  }

  private List<FindCredentialResult> findMatchingName(final String nameLike) {
    final List<FindCredentialResult> credentialResults = jdbcTemplate.query(
      " select name.name, credential_version.version_created_at from ("
        + "   select"
        + "     max(version_created_at) as version_created_at,"
        + "     credential_uuid"
        + "   from credential_version group by credential_uuid"
        + " ) as credential_version inner join ("
        + "   select * from credential"
        + "     where lower(name) like lower(?)"
        + " ) as name"
        + " on credential_version.credential_uuid = name.uuid"
        + " order by version_created_at desc",
      new Object[]{nameLike},
      (rowSet, rowNum) -> {
        final Instant versionCreatedAt = Instant
          .ofEpochMilli(rowSet.getLong("version_created_at"));
        final String name = rowSet.getString("name");
        return new FindCredentialResult(versionCreatedAt, name);
      }
    );
    return credentialResults;
  }
}
