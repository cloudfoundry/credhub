package org.cloudfoundry.credhub.view;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateCredentialsView {

  private final List<CertificateCredentialView> certificates;

  @SuppressWarnings("rawtypes")
  public CertificateCredentialsView(final List<CertificateCredentialView> certificates) {
    super();
    this.certificates = certificates;
  }

  @JsonProperty
  public List<CertificateCredentialView> getCertificates() {
    return certificates;
  }
}
