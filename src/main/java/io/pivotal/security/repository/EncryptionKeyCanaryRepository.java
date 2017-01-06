package io.pivotal.security.repository;

import io.pivotal.security.entity.EncryptionKeyCanary;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface EncryptionKeyCanaryRepository extends JpaRepository<EncryptionKeyCanary, UUID> {
}
