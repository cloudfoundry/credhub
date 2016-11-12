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

  @Autowired
  public NamedCertificateAuthorityDataService(NamedCertificateAuthorityRepository namedCertificateAuthorityRepository) {
    this.namedCertificateAuthorityRepository = namedCertificateAuthorityRepository;
  }

  public NamedCertificateAuthority save(NamedCertificateAuthority certificateAuthority) {
    return namedCertificateAuthorityRepository.save(certificateAuthority);
  }

  public NamedCertificateAuthority findMostRecent(String name) {
    return namedCertificateAuthorityRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }

  public NamedCertificateAuthority findByUuid(String uuid) {
    return namedCertificateAuthorityRepository.findOneByUuid(UUID.fromString(uuid));
  }

  public List<NamedCertificateAuthority> findAllByName(String name) {
    return namedCertificateAuthorityRepository.findAllByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }
}
