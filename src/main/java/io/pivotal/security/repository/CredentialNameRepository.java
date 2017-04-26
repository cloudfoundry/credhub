package io.pivotal.security.repository;

import io.pivotal.security.entity.CredentialName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface CredentialNameRepository extends JpaRepository<CredentialName, UUID> {

  @Transactional
  long deleteByNameIgnoreCase(String name);

  CredentialName findOneByNameIgnoreCase(String name);
}
