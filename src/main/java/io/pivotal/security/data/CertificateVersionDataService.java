package io.pivotal.security.data;

import io.pivotal.security.domain.CredentialFactory;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.repository.CredentialVersionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

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
}
