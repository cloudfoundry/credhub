package org.cloudfoundry.credhub.repositories

import org.cloudfoundry.credhub.data.PermissionData
import org.springframework.context.annotation.Profile
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Profile("!stub-repositories")
interface PermissionRepository : JpaRepository<PermissionData, UUID> {
    fun findAllByPath(path: String?): List<PermissionData>

    fun findByPathAndActor(
        path: String,
        actor: String,
    ): PermissionData?

    fun findByUuid(uuid: UUID): PermissionData?

    @Query(value = "select * from permission where path IN ?1 AND actor=?2", nativeQuery = true)
    fun findByPathsAndActor(
        paths: List<String>,
        actor: String,
    ): List<PermissionData>

    @Query(value = "select path from permission where read_permission = TRUE and actor = ?1", nativeQuery = true)
    fun findAllPathsForActorWithReadPermission(actor: String): List<String>

    @Transactional
    fun deleteByPathAndActor(
        path: String,
        actor: String,
    ): Long
}
