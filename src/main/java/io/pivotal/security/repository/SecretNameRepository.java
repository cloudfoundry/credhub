package io.pivotal.security.repository;

import io.pivotal.security.entity.SecretName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

public interface SecretNameRepository extends JpaRepository<SecretName, UUID> {

  @Transactional
  long deleteByNameIgnoreCase(String name);

  SecretName findOneByNameIgnoreCase(String name);
}
