package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class CertificateVersionDataService {

  private final CredentialVersionRepository credentialVersionRepository;
  private CredentialFactory credentialFactory;
  private CredentialDataService credentialDataService;

  @Autowired
  public CertificateVersionDataService(
      CredentialVersionRepository credentialVersionRepository,
      CredentialFactory credentialFactory, CredentialDataService credentialDataService) {
    this.credentialVersionRepository = credentialVersionRepository;
    this.credentialFactory = credentialFactory;
    this.credentialDataService = credentialDataService;
  }

  public CredentialVersion findActive(String caName) {
    Credential credential = credentialDataService.find(caName);

    if (credential == null) {
      return null;
    } else {
      return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
          .findLatestNonTransitionalCertificateVersion(credential.getUuid()));
    }
  }

  public CredentialVersion findByCredentialUUID(String uuid) {
    return credentialFactory.makeCredentialFromEntity(credentialVersionRepository
        .findLatestNonTransitionalCertificateVersion(UUID.fromString(uuid)));
  }

  public List<CredentialVersion> findActiveWithTransitional(String certificateName) {
    ArrayList<CredentialVersion> result = new ArrayList<>();
    Credential credential = credentialDataService.find(certificateName);
    UUID uuid = credential.getUuid();

    if (credential == null) {
      return null;
    } else {
      CredentialVersionData active = credentialVersionRepository.findLatestNonTransitionalCertificateVersion(uuid);
      if (active != null) {
        result.add(credentialFactory.makeCredentialFromEntity(active));
      }

      CredentialVersionData transitional = credentialVersionRepository.findTransitionalCertificateVersion(uuid);
      if (transitional != null) {
        result.add(credentialFactory.makeCredentialFromEntity(transitional));
      }
      return result;
    }
  }

  public List<CredentialVersion> findAllVersions(UUID uuid) {
    List<CredentialVersionData> credentialVersionDataList =
        credentialVersionRepository.
            findAllByCredentialUuidAndTypeOrderByVersionCreatedAtDesc(
                uuid, CertificateCredentialVersionData.CREDENTIAL_DATABASE_TYPE);
    return credentialFactory.makeCredentialsFromEntities(credentialVersionDataList);
  }

  public void deleteVersion(UUID versionUuid) {
    credentialVersionRepository.delete(versionUuid);
  }

  public CertificateCredentialVersion findVersion(UUID versionUuid) {
    CredentialVersionData credentialVersion = credentialVersionRepository.findOneByUuid(versionUuid);
    return (CertificateCredentialVersion) credentialFactory.makeCredentialFromEntity(credentialVersion);
  }

  public void setTransitionalVersion(UUID newTransitionalVersionUuid) {
    CertificateCredentialVersionData newTransitionalCertificate = (CertificateCredentialVersionData)credentialVersionRepository.findOneByUuid(newTransitionalVersionUuid);
    newTransitionalCertificate.setTransitional(true);
    credentialVersionRepository.save(newTransitionalCertificate);
  }

  public void unsetTransitionalVerison(UUID certificateUuid) {
    CertificateCredentialVersionData transitionalCertificate = (CertificateCredentialVersionData)credentialVersionRepository.findTransitionalCertificateVersion(certificateUuid);
    if (transitionalCertificate != null) {
      transitionalCertificate.setTransitional(false);
      credentialVersionRepository.save(transitionalCertificate);
    }
  }
}
