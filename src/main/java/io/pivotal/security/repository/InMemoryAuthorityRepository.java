package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedCertificateAuthority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InMemoryAuthorityRepository extends JpaRepository<NamedCertificateAuthority, Long> {
  NamedCertificateAuthority findOneByName(String name);
}
