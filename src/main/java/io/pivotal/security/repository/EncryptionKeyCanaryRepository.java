package io.pivotal.security.repository;

import io.pivotal.security.entity.EncryptionKeyCanary;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EncryptionKeyCanaryRepository extends JpaRepository<EncryptionKeyCanary, UUID> {

}
