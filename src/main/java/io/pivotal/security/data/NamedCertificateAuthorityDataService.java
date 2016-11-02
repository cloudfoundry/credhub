package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.NamedCertificateAuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class NamedCertificateAuthorityDataService {
  @Autowired
  NamedCertificateAuthorityRepository certificateAuthorityRepository;

  public NamedCertificateAuthority save(NamedCertificateAuthority certificateAuthority) {
    return certificateAuthorityRepository.save(certificateAuthority);
  }

  public NamedCertificateAuthority find(String name) {
    return certificateAuthorityRepository.findOneByNameIgnoreCase(name);
  }

  public NamedCertificateAuthority findOneByUuid(String uuid) {
    return certificateAuthorityRepository.findOneByUuid(uuid);
  }
}
