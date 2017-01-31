package io.pivotal.security.data;

import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class CertificateAuthorityService {

  private CertificateAuthorityDataService certificateAuthorityDataService;

  @Autowired
  public CertificateAuthorityService(CertificateAuthorityDataService certificateAuthorityDataService) {
    this.certificateAuthorityDataService = certificateAuthorityDataService;
  }

  public NamedCertificateAuthority findMostRecent(String caName) {
    NamedCertificateAuthority mostRecentCA = certificateAuthorityDataService.findMostRecent(caName);

    if (mostRecentCA == null) {
      if ("default".equals(caName)) {
        throw new ParameterizedValidationException("error.default_ca_required");
      } else {
        throw new ParameterizedValidationException("error.ca_not_found");
      }
    }

    return mostRecentCA;
  }
}