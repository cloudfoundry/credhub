package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.service.EncryptionKeyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Slice;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

import static io.pivotal.security.repository.CertificateAuthorityRepository.CERTIFICATE_AUTHORITY_BATCH_SIZE;

@Service
public class CertificateAuthorityDataService {
  private final CertificateAuthorityRepository certificateAuthorityRepository;
  private final EncryptionKeyService encryptionKeyService;

  @Autowired
  public CertificateAuthorityDataService(
      CertificateAuthorityRepository certificateAuthorityRepository,
      EncryptionKeyService encryptionKeyService
  ) {
    this.certificateAuthorityRepository = certificateAuthorityRepository;
    this.encryptionKeyService = encryptionKeyService;
  }

  public NamedCertificateAuthority save(NamedCertificateAuthority certificateAuthority) {
    if (certificateAuthority.getEncryptionKeyUuid() == null) {
      certificateAuthority.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
    }
    return certificateAuthorityRepository.save(certificateAuthority);
  }

  public NamedCertificateAuthority findMostRecent(String name) {
    return certificateAuthorityRepository.findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(name);
  }

  public NamedCertificateAuthority findByUuid(String uuid) {
    return certificateAuthorityRepository.findOneByUuid(UUID.fromString(uuid));
  }

  public List<NamedCertificateAuthority> findAllByName(String name) {
    return certificateAuthorityRepository.findAllByNameIgnoreCaseOrderByVersionCreatedAtDesc(name);
  }

  public Slice<NamedCertificateAuthority> findNotEncryptedByActiveKey() {
    return certificateAuthorityRepository.findByEncryptionKeyUuidNot(
        encryptionKeyService.getActiveEncryptionKeyUuid(),
        new PageRequest(0, CERTIFICATE_AUTHORITY_BATCH_SIZE)
    );
  }
}
