package org.cloudfoundry.credhub.repository;


import org.cloudfoundry.credhub.entity.PermissionData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface PermissionRepository extends JpaRepository<PermissionData, UUID> {
  List<PermissionData> findAllByPath(String path);

  List<PermissionData> findAllByActor(String actor);

  PermissionData findByPathAndActor(String path, String actor);

  PermissionData findByUuid(UUID uuid);

  @Query(value = "select * from permission where path IN ?1 AND actor=?2",  nativeQuery = true)
  List<PermissionData> findByPathsAndActor(List<String> paths, String actor);

  @Query(value = "select path from permission where read_permission = TRUE and actor = ?1",  nativeQuery = true)
  List<String> findAllPathsForActorWithReadPermission(String actor);

  @Transactional
  long deleteByPathAndActor(String path, String actor);
}
