package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedPasswordSecret;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface PasswordRepository extends JpaRepository<NamedPasswordSecret, UUID> {
  List<NamedPasswordSecret> findByParameterEncryptionKeyUuidNot(UUID parameterEncryptionKeyUuid);
}
