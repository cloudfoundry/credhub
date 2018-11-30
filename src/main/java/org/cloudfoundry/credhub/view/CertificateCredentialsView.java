package org.cloudfoundry.credhub.view;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateCredentialsView {

  private List<CertificateCredentialView> certificates;

  @SuppressWarnings("rawtypes")
  public CertificateCredentialsView(List<CertificateCredentialView> certificates) {
    this.certificates = certificates;
  }

  @JsonProperty
  public List<CertificateCredentialView> getCertificates() {
    return certificates;
  }
}
