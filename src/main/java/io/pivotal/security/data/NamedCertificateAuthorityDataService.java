package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.SecretEncryptionHelper;
import io.pivotal.security.repository.NamedCertificateAuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;

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

  public NamedCertificateAuthority saveWithEncryption(NamedCertificateAuthority certificateAuthority) {
    secretEncryptionHelper.refreshEncryptedValue(certificateAuthority, certificateAuthority.getPrivateKey());
    return namedCertificateAuthorityRepository.save(certificateAuthority);
  }

  public NamedCertificateAuthority findMostRecentByNameWithDecryption(String name) {
    NamedCertificateAuthority foundCa = namedCertificateAuthorityRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
    if (foundCa != null) {
      return foundCa.setPrivateKey(secretEncryptionHelper.retrieveClearTextValue(foundCa));
    }
    return foundCa;
  }

  public NamedCertificateAuthority findOneByUuidWithDecryption(String uuid) {
    NamedCertificateAuthority foundCa = namedCertificateAuthorityRepository.findOneByUuid(UUID.fromString(uuid));
    if (foundCa != null) {
      return foundCa.setPrivateKey(secretEncryptionHelper.retrieveClearTextValue(foundCa));
    }
    return foundCa;
  }

  public List<NamedCertificateAuthority> findAllByName(String name) {
    return newArrayList();
  }
}
