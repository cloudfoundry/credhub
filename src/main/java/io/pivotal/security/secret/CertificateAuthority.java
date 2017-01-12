package io.pivotal.security.secret;

public class CertificateAuthority {
  private final String type;
  private final String certificate;
  private final String privateKey;

  public CertificateAuthority(String type, String certificate, String privateKey) {
    this.type = type;
    this.certificate = certificate;
    this.privateKey = privateKey;
  }

  public String getType() {
    return type;
  }

  public String getCertificate() {
    return certificate;
  }

  public String getPrivateKey() {
    return privateKey;
  }
}
