package org.cloudfoundry.credhub.repository;


import org.cloudfoundry.credhub.entity.PermissionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<PermissionData, UUID> {

  List<PermissionData> findAllByCredentialUuid(UUID name);
  PermissionData findByCredentialAndActor(Credential credential, String actor);

  @Transactional
  long deleteByCredentialAndActor(Credential credential, String actor);
}
