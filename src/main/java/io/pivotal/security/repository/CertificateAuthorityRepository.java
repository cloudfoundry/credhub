package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedCertificateAuthority;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CertificateAuthorityRepository extends JpaRepository<NamedCertificateAuthority, UUID> {
  int CERTIFICATE_AUTHORITY_BATCH_SIZE = 50;

  List<NamedCertificateAuthority> findAllByNameIgnoreCaseOrderByVersionCreatedAtDesc(String name);
  NamedCertificateAuthority findFirstByNameIgnoreCaseOrderByVersionCreatedAtDesc(String name);
  NamedCertificateAuthority findOneByUuid(UUID uuid);
  Slice<NamedCertificateAuthority> findByEncryptionKeyUuidNot(UUID encryptionKeyUuid, Pageable page);
}
