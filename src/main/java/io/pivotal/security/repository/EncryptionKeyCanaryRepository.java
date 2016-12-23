package io.pivotal.security.repository;

import io.pivotal.security.entity.EncryptionKeyCanary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EncryptionKeyCanaryRepository extends JpaRepository<EncryptionKeyCanary, Long> {
  EncryptionKeyCanary findOneByName(String name);
}
