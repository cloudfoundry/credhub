package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedCertificateAuthority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NamedCertificateAuthorityRepository extends JpaRepository<NamedCertificateAuthority, Long> {
  NamedCertificateAuthority findOneByNameIgnoreCase(String name);
  NamedCertificateAuthority findOneByUuid(String uuid);
}
