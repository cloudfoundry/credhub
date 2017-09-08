package io.pivotal.security.repository;

import io.pivotal.security.entity.CertificateCredentialData;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CertificateCredentialRepository extends JpaRepository<CertificateCredentialData, UUID> {
  List<CertificateCredentialData> findAllCertificateCredentialDataByCaName (String caName);
}
