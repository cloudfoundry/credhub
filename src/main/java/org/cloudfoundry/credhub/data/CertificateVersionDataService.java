package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.domain.CredentialFactory;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
}
