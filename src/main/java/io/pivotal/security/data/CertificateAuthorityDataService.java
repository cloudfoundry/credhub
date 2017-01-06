package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class CertificateAuthorityDataService {
  private final CertificateAuthorityRepository certificateAuthorityRepository;
  private final EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  public CertificateAuthorityDataService(
      CertificateAuthorityRepository certificateAuthorityRepository,
      EncryptionKeyCanaryDataService encryptionKeyCanaryDataService
  ) {
    this.certificateAuthorityRepository = certificateAuthorityRepository;
    this.encryptionKeyCanaryDataService = encryptionKeyCanaryDataService;
  }

  public NamedCertificateAuthority save(NamedCertificateAuthority certificateAuthority) {
    if (certificateAuthority.getEncryptionKeyUuid() == null) {
      certificateAuthority.setEncryptionKeyUuid(encryptionKeyCanaryDataService.getOne().getUuid());
    }
    return certificateAuthorityRepository.save(certificateAuthority);
  }

  public NamedCertificateAuthority findMostRecent(String name) {
    return certificateAuthorityRepository.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }

  public NamedCertificateAuthority findByUuid(String uuid) {
    return certificateAuthorityRepository.findOneByUuid(UUID.fromString(uuid));
  }

  public List<NamedCertificateAuthority> findAllByName(String name) {
    return certificateAuthorityRepository.findAllByNameIgnoreCaseOrderByUpdatedAtDesc(name);
  }
}
