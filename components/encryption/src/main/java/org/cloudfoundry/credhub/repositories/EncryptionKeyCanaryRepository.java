package org.cloudfoundry.credhub.repositories;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;

public interface EncryptionKeyCanaryRepository extends JpaRepository<EncryptionKeyCanary, UUID> {
  @Transactional
  void deleteByUuidIn(List<UUID> uuids);
}
