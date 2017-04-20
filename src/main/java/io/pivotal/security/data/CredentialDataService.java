package io.pivotal.security.data;

import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.UserCredential;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.entity.CredentialName;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedJsonSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.NamedRsaSecretData;
import io.pivotal.security.entity.NamedSecretData;
import io.pivotal.security.entity.NamedSshSecretData;
import io.pivotal.security.entity.NamedUserSecretData;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.repository.CredentialNameRepository;
import io.pivotal.security.repository.CredentialRepository;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.view.CredentialView;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.data.domain.SliceImpl;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.repository.CredentialRepository.BATCH_SIZE;

@Service
public class CredentialDataService {

  protected final CredentialRepository credentialRepository;
  private final CredentialNameRepository credentialNameRepository;
  private final JdbcTemplate jdbcTemplate;
  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final String findMatchingNameQuery =
      " select name.name, secret.version_created_at from ("
          + "   select"
          + "     max(version_created_at) as version_created_at,"
          + "     credential_name_uuid"
          + "   from named_secret group by credential_name_uuid"
          + " ) as secret inner join ("
          + "   select * from credential_name"
          + "     where lower(name) like lower(?)"
          + " ) as name"
          + " on secret.credential_name_uuid = name.uuid"
          + " order by version_created_at desc";
  private Encryptor encryptor;
  private NamedSecretData dao;

  @Autowired
  protected CredentialDataService(
      CredentialRepository credentialRepository,
      CredentialNameRepository credentialNameRepository,
      JdbcTemplate jdbcTemplate,
      EncryptionKeyCanaryMapper encryptionKeyCanaryMapper,
      Encryptor encryptor
  ) {
    this.credentialRepository = credentialRepository;
    this.credentialNameRepository = credentialNameRepository;
    this.jdbcTemplate = jdbcTemplate;
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptor = encryptor;
  }

  public <Z extends Credential> Z save(Z namedSecret) {
    return (Z) namedSecret.save(this);
  }

  public <Z extends Credential> Z save(NamedSecretData namedSecret) {
    if (namedSecret.getEncryptionKeyUuid() == null) {
      namedSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
    }

    CredentialName credentialName = namedSecret.getCredentialName();

    if (credentialName.getUuid() == null) {
      namedSecret.setCredentialName(credentialNameRepository.saveAndFlush(credentialName));
    }

    return (Z) wrap(credentialRepository.saveAndFlush(namedSecret));
  }

  public List<String> findAllPaths() {
    return findAllPaths(true);
  }

  private List<String> findAllPaths(Boolean findPaths) {
    if (!findPaths) {
      return newArrayList();
    }

    return credentialRepository.findAll().stream()
        .map(namedSecretData -> namedSecretData.getCredentialName().getName())
        .flatMap(CredentialDataService::fullHierarchyForPath)
        .distinct()
        .sorted()
        .collect(Collectors.toList());
  }

  private static Stream<String> fullHierarchyForPath(String path) {
    String[] components = path.split("/");
    if (components.length > 1) {
      StringBuilder currentPath = new StringBuilder();
      List<String> pathSet = new ArrayList<>();
      for (int i = 0; i < components.length - 1; i++) {
        String element = components[i];
        currentPath.append(element).append('/');
        pathSet.add(currentPath.toString());
      }
      return pathSet.stream();
    } else {
      return Stream.of();
    }
  }

  public Credential findMostRecent(String name) {
    CredentialName credentialName = credentialNameRepository
        .findOneByNameIgnoreCase(StringUtils.prependIfMissing(name, "/"));

    if (credentialName == null) {
      return null;
    } else {
      return wrap(credentialRepository
          .findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(credentialName.getUuid()));
    }
  }

  public Credential findByUuid(String uuid) {
    return wrap(credentialRepository.findOneByUuid(UUID.fromString(uuid)));
  }

  public List<CredentialView> findContainingName(String name) {
    return findMatchingName("%" + name + "%");
  }

  public List<CredentialView> findStartingWithPath(String path) {
    path = StringUtils.prependIfMissing(path, "/");
    path = StringUtils.appendIfMissing(path, "/");

    return findMatchingName(path + "%");
  }

  public boolean delete(String name) {
    long numDeleted = credentialNameRepository.deleteByNameIgnoreCase(
        StringUtils.prependIfMissing(name, "/"));
    return numDeleted > 0;
  }

  public List<Credential> findAllByName(String name) {
    CredentialName credentialName = credentialNameRepository
        .findOneByNameIgnoreCase(StringUtils.prependIfMissing(name, "/"));

    return credentialName != null ? wrap(credentialRepository.findAllByCredentialNameUuid(credentialName.getUuid()))
        : newArrayList();
  }

  public Long count() {
    return credentialRepository.count();
  }

  public Long countAllNotEncryptedByActiveKey() {
    return credentialRepository.countByEncryptionKeyUuidNot(
        encryptionKeyCanaryMapper.getActiveUuid()
    );
  }

  public Long countEncryptedWithKeyUuidIn(List<UUID> uuids) {
    return credentialRepository.countByEncryptionKeyUuidIn(uuids);
  }

  public Slice<Credential> findEncryptedWithAvailableInactiveKey() {
    final Slice<NamedSecretData> namedSecretDataSlice = credentialRepository.findByEncryptionKeyUuidIn(
        encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys(),
        new PageRequest(0, BATCH_SIZE)
    );
    return new SliceImpl(wrap(namedSecretDataSlice.getContent()));
  }

  private List<CredentialView> findMatchingName(String nameLike) {
    return jdbcTemplate.query(
        findMatchingNameQuery,
        new Object[]{nameLike},
        (rowSet, rowNum) -> {
          final Instant versionCreatedAt = Instant
              .ofEpochMilli(rowSet.getLong("version_created_at"));
          final String name = rowSet.getString("name");
          return new CredentialView(versionCreatedAt, name);
        }
    );
  }

  private List<Credential> wrap(List<NamedSecretData> daos) {
    return daos.stream().map(this::wrap).collect(Collectors.toList());
  }

  private Credential wrap(NamedSecretData dao) {
    if (dao == null) {
      return null;
    }
    Credential returnValue;
    if (dao instanceof NamedCertificateSecretData) {
      returnValue = new CertificateCredential((NamedCertificateSecretData) dao);
    } else if (dao instanceof NamedPasswordSecretData) {
      returnValue = new PasswordCredential((NamedPasswordSecretData) dao);
    } else if (dao instanceof NamedRsaSecretData) {
      returnValue = new RsaCredential((NamedRsaSecretData) dao);
    } else if (dao instanceof NamedSshSecretData) {
      returnValue = new SshCredential((NamedSshSecretData) dao);
    } else if (dao instanceof NamedValueSecretData) {
      returnValue = new ValueCredential((NamedValueSecretData) dao);
    } else if (dao instanceof NamedJsonSecretData) {
      returnValue = new JsonCredential((NamedJsonSecretData) dao);
    } else if (dao instanceof NamedUserSecretData) {
      returnValue = new UserCredential((NamedUserSecretData) dao);
    } else {
      throw new RuntimeException("Unrecognized type: " + dao.getClass().getName());
    }

    returnValue.setEncryptor(encryptor);
    return returnValue;
  }
}
