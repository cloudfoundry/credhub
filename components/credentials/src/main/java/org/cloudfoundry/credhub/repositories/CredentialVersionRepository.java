package org.cloudfoundry.credhub.repositories;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import org.cloudfoundry.credhub.entity.CredentialVersionData;

public interface CredentialVersionRepository extends JpaRepository<CredentialVersionData, UUID> {

  CredentialVersionData findOneByUuid(UUID uuid);

  @Query(value = "select * from credential_version "
    + "left join certificate_credential on credential_version.uuid = certificate_credential.uuid "
    + "where credential_uuid = ?1 "
    + "and certificate_credential.transitional = false "
    + "order by version_created_at desc "
    + "limit 1", nativeQuery = true)
  CredentialVersionData findLatestNonTransitionalCertificateVersion(UUID credentialUUID);

  @Query(value = "select * from credential_version "
    + "left join certificate_credential on credential_version.uuid = certificate_credential.uuid "
    + "where credential_uuid = ?1 "
    + "and certificate_credential.transitional = true "
    + "order by version_created_at desc "
    + "limit 1", nativeQuery = true)
  CredentialVersionData findTransitionalCertificateVersion(UUID credentialUUID);

  Long countByEncryptedCredentialValueEncryptionKeyUuidIn(Collection<UUID> encryptionKeyUuids);

  List<CredentialVersionData> findByEncryptedCredentialValueEncryptionKeyUuidIn(List<UUID> encryptionKeyUuids);

  List<CredentialVersionData> findAllByCredentialUuidOrderByVersionCreatedAtDesc(UUID uuid);

  List<CredentialVersionData> findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(UUID uuid, String credentialType);

  CredentialVersionData findFirstByCredentialUuidOrderByVersionCreatedAtDesc(UUID uuid);

  @Query(value = "select * from credential_version "
    + "inner join certificate_credential on credential_version.uuid = certificate_credential.uuid "
    + "where expiry_date IS NULL order by version_created_at limit 1000 offset ?1", nativeQuery = true)
  List<CredentialVersionData> findUpTo1000VersionsWithNullExpirationDate(int offset);

  @Query(value = "select count(*) from credential_version "
    + "inner join certificate_credential on credential_version.uuid = certificate_credential.uuid "
    + "where expiry_date IS NULL", nativeQuery = true)
  int countVersionsWithNullExpirationDate();
}
