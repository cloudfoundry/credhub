package org.cloudfoundry.credhub.repository;

import org.cloudfoundry.credhub.entity.Credential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

public interface CredentialRepository extends JpaRepository<Credential, UUID> {

  @Transactional
  long deleteByNameIgnoreCase(String name);

  Credential findOneByUuid(UUID uuid);

  @Query(value = "select credential.uuid, credential.name from certificate_credential "
      + "left join credential_version on certificate_credential.uuid = credential_version.uuid "
      + "join credential on credential.uuid = credential_version.credential_uuid "
      + "where credential.uuid = ?1"
      , nativeQuery = true)
  Credential findCertificateByUuid(UUID uuid);

  Credential findOneByNameIgnoreCase(String name);

  @Query(value = "select credential.uuid, credential.name from certificate_credential "
      + "left join credential_version on certificate_credential.uuid = credential_version.uuid "
      + "join credential on credential.uuid = credential_version.credential_uuid "
      + "group by credential.uuid"
      , nativeQuery = true)
  List<Credential> findAllCertificates();

  @Query(value = "select credential.uuid, credential.name from certificate_credential "
      + "left join credential_version on certificate_credential.uuid = credential_version.uuid "
      + "join credential on credential.uuid = credential_version.credential_uuid "
      + "where credential.name = ?1 limit 1 "
      , nativeQuery = true)
  Credential findCertificateByName(String name);
}
