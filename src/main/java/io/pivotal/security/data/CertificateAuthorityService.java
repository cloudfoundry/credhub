package io.pivotal.security.data;

import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.credential.Certificate;
import io.pivotal.security.util.CertificateReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateAuthorityService {

  private final CredentialDataService credentialDataService;

  @Autowired
  public CertificateAuthorityService(CredentialDataService credentialDataService) {
    this.credentialDataService = credentialDataService;
  }

  public Certificate findMostRecent(String caName) throws ParameterizedValidationException {
    Credential mostRecent = credentialDataService.findMostRecent(caName);
    if (CertificateCredential.class.isInstance(mostRecent)) {
      CertificateCredential certificateCredential = (CertificateCredential) mostRecent;

      if (!new CertificateReader(certificateCredential.getCertificate()).isCa()) {
        throw new ParameterizedValidationException("error.cert_not_ca");
      }

      return new Certificate(null, certificateCredential.getCertificate(),
          certificateCredential.getPrivateKey());
    } else {
      throw new ParameterizedValidationException("error.ca_not_found");
    }
  }

}
