package io.pivotal.security.repository;

import io.pivotal.security.entity.NamedSecretData;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SecretRepository extends JpaRepository<NamedSecretData, UUID> {

  int BATCH_SIZE = 50;

  NamedSecretData findOneByUuid(UUID uuid);

  Long countByEncryptionKeyUuidNot(UUID encryptionKeyUuid);

  Long countByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);

  Slice<NamedSecretData> findByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page);

  List<NamedSecretData> findAllBySecretNameUuid(UUID uuid);

  NamedSecretData findFirstBySecretNameUuidOrderByVersionCreatedAtDesc(UUID uuid);
}
