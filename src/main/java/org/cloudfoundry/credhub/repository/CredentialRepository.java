package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

  @Transactional
  long deleteByNameIgnoreCase(String name);

  Credential findOneByNameIgnoreCase(String name);
}
