package io.pivotal.security.repository;

import io.pivotal.security.entity.CredentialVersion;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CredentialVersionRepository extends JpaRepository<CredentialVersion, UUID> {

  int BATCH_SIZE = 50;

  CredentialVersion findOneByUuid(UUID uuid);

  Long countByEncryptedCredentialValueEncryptionKeyUuidNot(UUID encryptionKeyUuid);

  Long countByEncryptedCredentialValueEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);

  Slice<CredentialVersion> findByEncryptedCredentialValueEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page);

  List<CredentialVersion> findAllByCredentialNameUuidOrderByVersionCreatedAtDesc(UUID uuid);

  CredentialVersion findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(UUID uuid);
}
