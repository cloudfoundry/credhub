package io.pivotal.security.secret;

public class Certificate implements Secret {
  private final String caCertificate;
  private final String certificate;
  private final String privateKey;

  public Certificate(String caCertificate, String certificate, String privateKey) {
    this.caCertificate = caCertificate;
    this.certificate = certificate;
    this.privateKey = privateKey;
  }

  public String getCaCertificate() {
    return caCertificate;
  }

  public String getCertificate() {
    return certificate;
  }

  public String getPrivateKey() {
    return privateKey;
  }
}
