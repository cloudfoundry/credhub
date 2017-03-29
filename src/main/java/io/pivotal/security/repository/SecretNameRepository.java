package io.pivotal.security.repository;

import io.pivotal.security.entity.SecretName;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

public interface SecretNameRepository extends JpaRepository<SecretName, UUID> {

  @Transactional
  long deleteByName(String name);

  SecretName findOneByNameIgnoreCase(String name);
}
