package org.cloudfoundry.credhub.repositories;

import java.util.List;
import java.util.UUID;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.jpa.repository.JpaRepository;

import org.cloudfoundry.credhub.entities.EncryptedValue;

public interface EncryptedValueRepository extends JpaRepository<EncryptedValue, UUID> {
  int BATCH_SIZE = 50;

  Long countByEncryptionKeyUuidNot(UUID encryptionKeyUuid);

  Long countByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);

  Slice<EncryptedValue> findByEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids, Pageable page);
}
