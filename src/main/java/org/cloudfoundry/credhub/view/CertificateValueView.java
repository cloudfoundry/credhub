package org.cloudfoundry.credhub.view;

import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;

class CertificateValueView {
  private final String ca;
  private final String certificate;
  private final String privateKey;

  public CertificateValueView(CertificateCredentialVersion value) {
    this.ca = value.getCa();
    this.certificate = value.getCertificate();
    this.privateKey = value.getPrivateKey();
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public String getCertificate() {
    return certificate;
  }

  public String getCa() {
    return ca;
  }
}
