package org.cloudfoundry.credhub.repositories

import java.util.UUID
import org.cloudfoundry.credhub.entity.Credential
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.transaction.annotation.Transactional

interface CredentialRepository : JpaRepository<Credential?, UUID?> {
    @Transactional
    fun deleteByNameIgnoreCase(name: String?): Long

    fun findOneByUuid(uuid: UUID?): Credential?
    @Query(value = "select credential.uuid, credential.name, credential.checksum from certificate_credential " +
        "left join credential_version on certificate_credential.uuid = credential_version.uuid " +
        "join credential on credential.uuid = credential_version.credential_uuid " +
        "where credential.uuid = ?1", nativeQuery = true)
    fun findCertificateByUuid(uuid: UUID?): Credential?

    fun findOneByNameIgnoreCase(name: String?): Credential?
    @Query(value = "select credential.uuid, credential.name, credential.checksum from certificate_credential " +
        "left join credential_version on certificate_credential.uuid = credential_version.uuid " +
        "join credential on credential.uuid = credential_version.credential_uuid " +
        "group by credential.uuid", nativeQuery = true)
    fun findAllCertificates(): List<Credential>

    @Query(value = "select credential.uuid, credential.name, credential.checksum from certificate_credential " +
        "left join credential_version on certificate_credential.uuid = credential_version.uuid " +
        "join credential on credential.uuid = credential_version.credential_uuid " +
        "where credential.name = ?1 limit 1 ", nativeQuery = true)
    fun findCertificateByName(name: String?): Credential?
}
