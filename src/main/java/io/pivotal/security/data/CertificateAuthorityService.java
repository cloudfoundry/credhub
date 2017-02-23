package io.pivotal.security.data;

import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.util.CertificateReader;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateAuthorityService {
  private final SecretDataService secretDataService;

  @Autowired
  public CertificateAuthorityService(SecretDataService secretDataService) {
    this.secretDataService = secretDataService;
  }

  public Certificate findMostRecent(String caName) throws ParameterizedValidationException {
    NamedSecret mostRecent = secretDataService.findMostRecent(caName);
    if (NamedCertificateSecret.class.isInstance(mostRecent)) {
      NamedCertificateSecret namedCertificateSecret = (NamedCertificateSecret) mostRecent;

      if (!new CertificateReader(namedCertificateSecret.getCertificate()).isCA()) {
        throw new ParameterizedValidationException("error.cert_not_ca");
      }

      return new Certificate(null, namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey());
    } else {
      throw new ParameterizedValidationException("error.ca_not_found");
    }
  }

}
