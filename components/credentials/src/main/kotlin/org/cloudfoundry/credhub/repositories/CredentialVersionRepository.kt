package org.cloudfoundry.credhub.repositories

import java.util.UUID
import org.cloudfoundry.credhub.entity.CredentialVersionData
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query

interface CredentialVersionRepository : JpaRepository<CredentialVersionData<*>?, UUID?> {
    fun findOneByUuid(uuid: UUID?): CredentialVersionData<*>?
    @Query(value = "select * from credential_version " +
        "left join certificate_credential on credential_version.uuid = certificate_credential.uuid " +
        "where credential_uuid = ?1 " +
        "and certificate_credential.transitional = false " +
        "order by version_created_at desc " +
        "limit 1", nativeQuery = true)
    fun findLatestNonTransitionalCertificateVersion(credentialUUID: UUID?): CredentialVersionData<*>?

    @Query(value = "select * from credential_version " +
        "left join certificate_credential on credential_version.uuid = certificate_credential.uuid " +
        "where credential_uuid = ?1 " +
        "and certificate_credential.transitional = true " +
        "order by version_created_at desc " +
        "limit 1", nativeQuery = true)
    fun findTransitionalCertificateVersion(credentialUUID: UUID?): CredentialVersionData<*>?

    fun countByEncryptedCredentialValueEncryptionKeyUuidIn(encryptionKeyUuids: Collection<UUID?>?): Long?
    fun findByEncryptedCredentialValueEncryptionKeyUuidIn(encryptionKeyUuids: List<UUID?>?): List<CredentialVersionData<*>?>
    fun findAllByCredentialUuidOrderByVersionCreatedAtDesc(uuid: UUID?): List<CredentialVersionData<*>?>
    fun findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(uuid: UUID?, credentialType: String?): List<CredentialVersionData<*>?>
    fun findFirstByCredentialUuidOrderByVersionCreatedAtDesc(uuid: UUID?): CredentialVersionData<*>?
    @Query(value = "select * from credential_version " +
        "inner join certificate_credential on credential_version.uuid = certificate_credential.uuid " +
        "where expiry_date IS NULL " +
        "or certificate_authority IS NULL " +
        "or self_signed IS NULL " +
        "order by version_created_at limit 1000 offset ?1", nativeQuery = true)
    fun findUpTo1000VersionsWithNullCertificateMetadata(offset: Int): List<CredentialVersionData<*>?>

    @Query(value = "select count(*) from credential_version " +
        "inner join certificate_credential on credential_version.uuid = certificate_credential.uuid " +
        "where expiry_date IS NULL " +
        "or certificate_authority IS NULL " +
        "or self_signed IS NULL", nativeQuery = true)
    fun countVersionsWithNullCertificateMetadata(): Int
}
