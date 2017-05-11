package io.pivotal.security.repository;


import io.pivotal.security.entity.AccessEntryData;
import io.pivotal.security.entity.CredentialName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AccessEntryRepository extends JpaRepository<AccessEntryData, UUID> {

  List<AccessEntryData> findAllByCredentialNameUuid(UUID name);

  AccessEntryData findByCredentialNameAndActor(CredentialName credentialName, String actor);
  AccessEntryData findByCredentialNameUuidAndActor(UUID uuid, String actor);
}
