package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.SecretEncryptionHelper;
import io.pivotal.security.repository.NamedCertificateAuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class NamedCertificateAuthorityDataService {
  private final NamedCertificateAuthorityRepository namedCertificateAuthorityRepository;
  private final SecretEncryptionHelper secretEncryptionHelper;

  @Autowired
  public NamedCertificateAuthorityDataService(NamedCertificateAuthorityRepository namedCertificateAuthorityRepository,
                                              SecretEncryptionHelper secretEncryptionHelper) {
    this.namedCertificateAuthorityRepository = namedCertificateAuthorityRepository;
    this.secretEncryptionHelper = secretEncryptionHelper;
  }

  public NamedCertificateAuthority save(NamedCertificateAuthority certificateAuthority) {
    return saveWithEncryption(certificateAuthority);
  }

  public NamedCertificateAuthority findMostRecent(String name) {
    return findMostRecentByNameWithDecryption(name);
  }

  public NamedCertificateAuthority findByUuid(String uuid) {
    return findOneByUuidWithDecryption(uuid);
  }

  private NamedCertificateAuthority saveWithEncryption(NamedCertificateAuthority certificateAuthority) {
    secretEncryptionHelper.refreshEncryptedValue(certificateAuthority, certificateAuthority.getPrivateKey());
    return namedCertificateAuthorityRepository.save(certificateAuthority);
  }

  private NamedCertificateAuthority findMostRecentByNameWithDecryption(String name) {
    NamedCertificateAuthority foundCa = namedCertificateAuthorityRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
    if (foundCa != null) {
      return foundCa.setPrivateKey(secretEncryptionHelper.retrieveClearTextValue(foundCa));
    }
    return foundCa;
  }

  private NamedCertificateAuthority findOneByUuidWithDecryption(String uuid) {
    NamedCertificateAuthority foundCa = namedCertificateAuthorityRepository.findOneByUuid(UUID.fromString(uuid));
    if (foundCa != null) {
      return foundCa.setPrivateKey(secretEncryptionHelper.retrieveClearTextValue(foundCa));
    }
    return foundCa;
  }

  public List<NamedCertificateAuthority> findAllByName(String name) {
    return namedCertificateAuthorityRepository.findAllByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }
}
