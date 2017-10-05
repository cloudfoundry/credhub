package io.pivotal.security.repository;

import io.pivotal.security.entity.CredentialData;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CredentialRepository extends JpaRepository<CredentialData, UUID> {

  int BATCH_SIZE = 50;

  CredentialData findOneByUuid(UUID uuid);

  Long countByEncryptedCredentialValueEncryptionKeyUuidNot(UUID encryptionKeyUuid);

  Long countByEncryptedCredentialValueEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);

  Slice<CredentialData> findByEncryptedCredentialValueEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page);

  List<CredentialData> findAllByCredentialNameUuidOrderByVersionCreatedAtDesc(UUID uuid);

  CredentialData findFirstByCredentialNameUuidOrderByVersionCreatedAtDesc(UUID uuid);
}
