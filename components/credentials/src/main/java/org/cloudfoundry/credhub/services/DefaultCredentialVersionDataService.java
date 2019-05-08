package org.cloudfoundry.credhub.services;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import com.google.common.collect.Lists;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.exceptions.MaximumSizeException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.views.FindCertificateResult;
import org.cloudfoundry.credhub.views.FindCredentialResult;

@SuppressWarnings({"PMD.TooManyMethods", "PMD.GodClass", })
@Service
public class DefaultCredentialVersionDataService implements CredentialVersionDataService {

  private final CredentialVersionRepository credentialVersionRepository;
  private final CredentialDataService credentialDataService;
  private final JdbcTemplate jdbcTemplate;
  private final CredentialFactory credentialFactory;
  private final CertificateVersionDataService certificateVersionDataService;

  @Autowired
  protected DefaultCredentialVersionDataService(
    final CredentialVersionRepository credentialVersionRepository,
    final CredentialDataService credentialDataService,
    final JdbcTemplate jdbcTemplate,
    final CredentialFactory credentialFactory,
    final CertificateVersionDataService certificateVersionDataService
  ) {
    super();
    this.credentialVersionRepository = credentialVersionRepository;
    this.credentialDataService = credentialDataService;
    this.jdbcTemplate = jdbcTemplate;
    this.credentialFactory = credentialFactory;
    this.certificateVersionDataService = certificateVersionDataService;
  }

  @Override
  public CredentialVersion save(final CredentialVersion credentialVersion) {
    return credentialVersion.save(this);
  }

  @SuppressFBWarnings(
    value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
    justification = "Let's refactor this class into kotlin"
  )
  @Override
  public CredentialVersion save(final CredentialVersionData credentialVersionData) {
    final Credential credential = credentialVersionData.getCredential();

    if (credential.getUuid() == null) {
      credentialVersionData.setCredential(credentialDataService.save(credential));
    } else {
      final CredentialVersion existingCredentialVersion = findMostRecent(credential.getName());
      if (existingCredentialVersion != null && !existingCredentialVersion.getCredentialType()
        .equals(credentialVersionData.getCredentialType())) {
        throw new ParameterizedValidationException(ErrorMessages.TYPE_MISMATCH);
      }
    }

    try {
      return credentialFactory
        .makeCredentialFromEntity(credentialVersionRepository.saveAndFlush(credentialVersionData));
    } catch (final DataIntegrityViolationException e) {
      throw new MaximumSizeException(e.getMessage());
    }
  }

  @Override
  public CredentialVersion findMostRecent(final String name) {
    final Credential credential = credentialDataService.find(name);

    if (credential == null) {
      return null;
    } else {
      return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
        .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid()));
    }
  }

  @Override
  public CredentialVersion findByUuid(final String uuid) {
    return credentialFactory
      .makeCredentialFromEntity(credentialVersionRepository.findOneByUuid(UUID.fromString(uuid)));
  }

  @Override
  public List<String> findAllCertificateCredentialsByCaName(final String caName) {
    final String query = "select distinct credential.name from "
      + "credential, credential_version, certificate_credential "
      + "where credential.uuid=credential_version.credential_uuid "
      + "and credential_version.uuid=certificate_credential.uuid "
      + "and lower(certificate_credential.ca_name) "
      + "like lower(?)";
    return jdbcTemplate.queryForList(query, String.class, caName);
  }

  @Override
  public List<FindCredentialResult> findContainingName(final String name) {
    return findContainingName(name, "");
  }

  @Override
  public List<FindCredentialResult> findContainingName(final String name, final String expiresWithinDays) {
    if (!"".equals(expiresWithinDays)) {
      return filterCertificates("%" + name + "%", expiresWithinDays);
    }
    return findMatchingName("%" + name + "%");
  }

  @Override
  public List<FindCredentialResult> findStartingWithPath(final String path) {
    return findStartingWithPath(path, "");
  }

  @Override
  public List<FindCredentialResult> findStartingWithPath(final String path, final String expiresWithinDays) {

    String adjustedPath = StringUtils.prependIfMissing(path, "/");
    adjustedPath = StringUtils.appendIfMissing(adjustedPath, "/");

    if (!"".equals(expiresWithinDays)) {
      return filterCertificates(adjustedPath + "%", expiresWithinDays);
    }

    return findMatchingName(adjustedPath + "%");
  }

  @Override
  public boolean delete(final String name) {
    return credentialDataService.delete(name);
  }

  @Override
  public List<CredentialVersion> findAllByName(final String name) {
    final Credential credential = credentialDataService.find(name);

    return credential != null ? credentialFactory.makeCredentialsFromEntities(
      credentialVersionRepository.findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid()))
      : Lists.newArrayList();
  }

  @Override
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
      return Lists.newArrayList();
    }
  }

  @Override
  public Map<UUID, Long> countByEncryptionKey() {
    final Map<UUID, Long> map = new HashMap<>();
    jdbcTemplate.query(
      " SELECT count(*) as count, encryption_key_uuid FROM credential_version " +
        "LEFT JOIN encrypted_value ON credential_version.encrypted_value_uuid = encrypted_value.uuid " +
        "GROUP BY encrypted_value.encryption_key_uuid",
      (rowSet, rowNum) -> map.put(toUUID(rowSet.getObject("encryption_key_uuid")), rowSet.getLong("count"))
    );
    return map;
  }

  @Override
  public List<CredentialVersion> findActiveByName(final String name) {
    final Credential credential = credentialDataService.find(name);
    final CredentialVersionData credentialVersionData;
    final List<CredentialVersion> result = Lists.newArrayList();
    if (credential != null) {
      credentialVersionData = credentialVersionRepository
        .findFirstByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid());

      if (credentialVersionData.getCredentialType().equals(CertificateCredentialVersionData.CREDENTIAL_TYPE)) {
        return certificateVersionDataService.findActiveWithTransitional(name);
      }
      result.add(credentialFactory.makeCredentialFromEntity(credentialVersionData));

      return result;
    } else {
      return Lists.newArrayList();
    }
  }

  @Override
  public Long count() {
    return credentialVersionRepository.count();
  }

  @Override
  public Long countEncryptedWithKeyUuidIn(final Collection<UUID> uuids) {
    return credentialVersionRepository.countByEncryptedCredentialValueEncryptionKeyUuidIn(uuids);
  }

  private UUID toUUID(final Object object) {
    if (object.getClass() == byte[].class) {
      final byte[] bytes = (byte[]) object;
      if (bytes.length != 16) {
        throw new IllegalArgumentException("Expected byte[] of length 16. Received length " + bytes.length);
      }
      int i = 0;
      long msl = 0;
      for (; i < 8; i++) {
        msl = (msl << 8) | (bytes[i] & 0xFF);
      }
      long lsl = 0;
      for (; i < 16; i++) {
        lsl = (lsl << 8) | (bytes[i] & 0xFF);
      }
      return new UUID(msl, lsl);
    } else if (object.getClass() == UUID.class) {
      return (UUID) object;
    } else {
      throw new IllegalArgumentException("Expected byte[] or UUID type. Received " + object.getClass().toString());
    }
  }

  private List<FindCredentialResult> filterCertificates(final String path, final String expiresWithinDays) {
    final String escapedPath = path.replace("_", "\\_");

    final Timestamp expiresTimestamp = Timestamp
      .from(Instant.now().plus(Duration.ofDays(Long.parseLong(expiresWithinDays))));

    final String query = "SELECT name.name,\n" +
                    "       latest_credential_version.version_created_at,\n" +
                    "       certificate_credential.expiry_date\n" +
                    "FROM (\n" +
                    "         SELECT credential_uuid, max(version_created_at) AS max_version_created_at\n" +
                    "         FROM credential_version\n" +
                    "         GROUP BY credential_uuid) AS credential_uuid_of_max_version_created_at\n" +
                    "         INNER JOIN (SELECT * FROM credential WHERE lower(name) LIKE lower(?)) AS name\n" +
                    "                    ON credential_uuid_of_max_version_created_at.credential_uuid = name.uuid\n" +
                    "         INNER JOIN credential_version AS latest_credential_version\n" +
                    "                    ON latest_credential_version.credential_uuid =\n" +
                    "                       credential_uuid_of_max_version_created_at.credential_uuid\n" +
                    "                        AND latest_credential_version.version_created_at =\n" +
                    "                            credential_uuid_of_max_version_created_at.max_version_created_at\n" +
                    "         INNER JOIN (SELECT * FROM certificate_credential) AS certificate_credential\n" +
                    "                    ON latest_credential_version.uuid = certificate_credential.uuid\n" +
                    "WHERE certificate_credential.expiry_date <= ?;";

    final List<FindCredentialResult> certificateResults = jdbcTemplate.query(query,
      new Object[]{escapedPath, expiresTimestamp},
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

  private List<FindCredentialResult> findMatchingName(final String nameLike) {
    final String escapedNameLike = nameLike.replace("_", "\\_");

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
      new Object[]{escapedNameLike},
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
