package org.cloudfoundry.credhub.data;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.utils.CertificateReader;

@Service
public class CertificateVersionDataService {

  private final CredentialVersionRepository credentialVersionRepository;
  private final CredentialFactory credentialFactory;
  private final CredentialDataService credentialDataService;

  @Autowired
  public CertificateVersionDataService(
    final CredentialVersionRepository credentialVersionRepository,
    final CredentialFactory credentialFactory, final CredentialDataService credentialDataService) {
    super();
    this.credentialVersionRepository = credentialVersionRepository;
    this.credentialFactory = credentialFactory;
    this.credentialDataService = credentialDataService;
  }

  public CredentialVersion findActive(final String caName) {
    final Credential credential = credentialDataService.find(caName);

    if (credential == null) {
      return null;
    } else {
      return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
        .findLatestNonTransitionalCertificateVersion(credential.getUuid()));
    }
  }

  public CredentialVersion findByCredentialUUID(final String uuid) {
    return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
      .findLatestNonTransitionalCertificateVersion(UUID.fromString(uuid)));
  }

  public List<CredentialVersion> findActiveWithTransitional(final String certificateName) {
    final List<CredentialVersion> result = new ArrayList<>();
    final Credential credential = credentialDataService.find(certificateName);

    if (credential == null) {
      return null;
    } else {
      final UUID uuid = credential.getUuid();

      final CredentialVersionData active = credentialVersionRepository.findLatestNonTransitionalCertificateVersion(uuid);
      if (active != null) {
        result.add(credentialFactory.makeCredentialFromEntity(active));
      }

      final CredentialVersionData transitional = credentialVersionRepository.findTransitionalCertificateVersion(uuid);
      if (transitional != null) {
        result.add(credentialFactory.makeCredentialFromEntity(transitional));
      }
      return result;
    }
  }

  public List<CredentialVersion> findAllVersions(final UUID uuid) {
    final List<CredentialVersionData> credentialVersionDataList =
      credentialVersionRepository.
        findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(
          uuid, CertificateCredentialVersionData.CREDENTIAL_DATABASE_TYPE);
    return credentialFactory.makeCredentialsFromEntities(credentialVersionDataList);
  }

  public List<CredentialVersion> findAllValidVersions(final UUID uuid) {
    final List<CredentialVersionData> credentialVersionDataList =
      credentialVersionRepository.
        findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(
          uuid, CertificateCredentialVersionData.CREDENTIAL_DATABASE_TYPE);

    final List<CredentialVersionData> validCredentialVersionDataList = new ArrayList<>();
    for (final CredentialVersionData credentialVersionData : credentialVersionDataList) {
      if (isValidCertificate(credentialVersionData)) {
        validCredentialVersionDataList.add(credentialVersionData);
      }
    }

    return credentialFactory.makeCredentialsFromEntities(validCredentialVersionDataList);
  }

  public void deleteVersion(final UUID versionUuid) {
    credentialVersionRepository.deleteById(versionUuid);
  }

  public CertificateCredentialVersion findVersion(final UUID versionUuid) {
    final CredentialVersionData credentialVersion = credentialVersionRepository.findOneByUuid(versionUuid);
    return (CertificateCredentialVersion) credentialFactory.makeCredentialFromEntity(credentialVersion);
  }

  public void setTransitionalVersion(final UUID newTransitionalVersionUuid) {
    final CertificateCredentialVersionData newTransitionalCertificate = (CertificateCredentialVersionData) credentialVersionRepository.findOneByUuid(newTransitionalVersionUuid);
    newTransitionalCertificate.setTransitional(true);
    credentialVersionRepository.save(newTransitionalCertificate);
  }

  public void unsetTransitionalVersion(final UUID certificateUuid) {
    final CertificateCredentialVersionData transitionalCertificate = (CertificateCredentialVersionData) credentialVersionRepository.findTransitionalCertificateVersion(certificateUuid);
    if (transitionalCertificate != null) {
      transitionalCertificate.setTransitional(false);
      credentialVersionRepository.save(transitionalCertificate);
    }
  }

  private boolean isValidCertificate(final CredentialVersionData credentialVersionData) {
    try {
      final CertificateCredentialVersionData cert = (CertificateCredentialVersionData) credentialVersionData;
      new CertificateReader(cert.getCertificate());
    } catch (Exception e) {
      return false;
    }
    return true;
  }
}
