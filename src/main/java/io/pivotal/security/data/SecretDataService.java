package io.pivotal.security.data;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.repository.SecretRepository.BATCH_SIZE;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedJsonSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedJsonSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.view.SecretView;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SecretDataService {

  protected final SecretRepository secretRepository;
  private final SecretNameRepository secretNameRepository;
  private final JdbcTemplate jdbcTemplate;
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final String findMatchingNameQuery =
      " select name.name, secret.version_created_at from ("
          + "   select"
          + "     max(version_created_at) as version_created_at,"
          + "     secret_name_uuid"
          + "   from named_secret group by secret_name_uuid"
          + " ) as secret inner join ("
          + "   select * from secret_name"
          + "     where lower(name) like lower(?)"
          + " ) as name"
          + " on secret.secret_name_uuid = name.uuid"
          + " order by version_created_at desc";
  private Encryptor encryptor;
  private NamedSecretData dao;

  @Autowired
  protected SecretDataService(
      SecretRepository secretRepository,
      SecretNameRepository secretNameRepository,
      JdbcTemplate jdbcTemplate,
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      Encryptor encryptor
  ) {
    this.secretRepository = secretRepository;
    this.secretNameRepository = secretNameRepository;
    this.jdbcTemplate = jdbcTemplate;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptor = encryptor;
  }

  private static String addLeadingSlashIfMissing(String name) {
    return StringUtils.prependIfMissing(name, "/");
  }

  public <Z extends NamedSecret> Z save(Z namedSecret) {
    return (Z) namedSecret.save(this);
  }

  public <Z extends NamedSecret> Z save(NamedSecretData namedSecret) {
    if (namedSecret.getEncryptionKeyUuid() == null) {
      namedSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
    }

    SecretName secretName = namedSecret.getSecretName();

    if (secretName.getUuid() == null) {
      namedSecret.setSecretName(secretNameRepository.saveAndFlush(secretName));
    }

    return (Z) wrap(secretRepository.saveAndFlush(namedSecret));
  }

  public List<String> findAllPaths() {
    return findAllPaths(true);
  }

  private List<String> findAllPaths(Boolean findPaths) {
    if (!findPaths) {
      return newArrayList();
    }

    return secretRepository.findAll().stream()
        .map(namedSecretData -> namedSecretData.getSecretName().getName())
        .flatMap(NamedSecretData::fullHierarchyForPath)
        .distinct()
        .sorted()
        .collect(Collectors.toList());
  }

  public NamedSecret findMostRecent(String name) {
    SecretName secretName = secretNameRepository
        .findOneByNameIgnoreCase(addLeadingSlashIfMissing(name));

    if (secretName == null) {
      return null;
    } else {
      return wrap(secretRepository
          .findFirstBySecretNameUuidOrderByVersionCreatedAtDesc(secretName.getUuid()));
    }
  }

  protected SecretName findSecretName(String name) {
    return secretNameRepository.findOneByNameIgnoreCase(addLeadingSlashIfMissing(name));
  }

  public NamedSecret findByUuid(String uuid) {
    return wrap(secretRepository.findOneByUuid(UUID.fromString(uuid)));
  }

  public NamedSecret findByUuid(UUID uuid) {
    return wrap(secretRepository.findOneByUuid(uuid));
  }

  public List<SecretView> findContainingName(String name) {
    return findMatchingName("%" + name + "%");
  }

  public List<SecretView> findStartingWithPath(String path) {
    path = addLeadingSlashIfMissing(path);
    path = StringUtils.appendIfMissing(path, "/");

    return findMatchingName(path + "%");
  }

  public long delete(String name) {
    SecretName secretName = secretNameRepository
        .findOneByNameIgnoreCase(addLeadingSlashIfMissing(name));

    if (secretName != null) {
      return secretNameRepository.deleteByName(secretName.getName());
    } else {
      return 0;
    }
  }

  public List<NamedSecret> findAllByName(String name) {
    SecretName secretName = secretNameRepository
        .findOneByNameIgnoreCase(addLeadingSlashIfMissing(name));

    return secretName != null ? wrap(secretRepository.findAllBySecretNameUuid(secretName.getUuid()))
        : newArrayList();
  }

  public Long count() {
    return secretRepository.count();
  }

  public Long countAllNotEncryptedByActiveKey() {
    return secretRepository.countByEncryptionKeyUuidNot(
        encryptionKeyCanaryMapper.getActiveUuid()
    );
  }

  public Long countEncryptedWithKeyUuidIn(List<UUID> uuids) {
    return secretRepository.countByEncryptionKeyUuidIn(uuids);
  }

  public Slice<NamedSecret> findEncryptedWithAvailableInactiveKey() {
    final Slice<NamedSecretData> namedSecretDataSlice = secretRepository.findByEncryptionKeyUuidIn(
        encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys(),
        new PageRequest(0, BATCH_SIZE)
    );
    return new SliceImpl(wrap(namedSecretDataSlice.getContent()));
  }

  private List<SecretView> findMatchingName(String nameLike) {
    return jdbcTemplate.query(
        findMatchingNameQuery,
        new Object[]{nameLike},
        (rowSet, rowNum) -> {
          final Instant versionCreatedAt = Instant
              .ofEpochMilli(rowSet.getLong("version_created_at"));
          final String name = rowSet.getString("name");
          return new SecretView(versionCreatedAt, name);
        }
    );
  }

  private List<NamedSecret> wrap(List<NamedSecretData> daos) {
    return daos.stream().map(this::wrap).collect(Collectors.toList());
  }

  private NamedSecret wrap(NamedSecretData dao) {
    if (dao == null) {
      return null;
    }
    NamedSecret returnValue;
    if (dao instanceof NamedCertificateSecretData) {
      returnValue = new NamedCertificateSecret((NamedCertificateSecretData) dao);
    } else if (dao instanceof NamedPasswordSecretData) {
      returnValue = new NamedPasswordSecret((NamedPasswordSecretData) dao);
    } else if (dao instanceof NamedRsaSecretData) {
      returnValue = new NamedRsaSecret((NamedRsaSecretData) dao);
    } else if (dao instanceof NamedSshSecretData) {
      returnValue = new NamedSshSecret((NamedSshSecretData) dao);
    } else if (dao instanceof NamedValueSecretData) {
      returnValue = new NamedValueSecret((NamedValueSecretData) dao);
    } else if (dao instanceof NamedJsonSecretData) {
      returnValue = new NamedJsonSecret((NamedJsonSecretData) dao);
    } else {
      throw new RuntimeException("Unrecognized type: " + dao.getClass().getName());
    }

    returnValue.setEncryptor(encryptor);
    return returnValue;
  }
}
