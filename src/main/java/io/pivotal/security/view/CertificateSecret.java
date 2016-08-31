package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateSecret;

import java.time.Instant;

public class CertificateSecret extends Secret {

  @JsonProperty("value")
  private CertificateBody certificateBody;

  public CertificateSecret(Instant updatedAt, String uuid, String ca, String certificate, String privateKey) {
    super(updatedAt, uuid);
    setCertificateBody(new CertificateBody(ca, certificate, privateKey));
  }

  public CertificateSecret(NamedCertificateSecret namedCertificateSecret) {
    this(namedCertificateSecret.getUpdatedAt(), namedCertificateSecret.getUuid(), namedCertificateSecret.getCa(), namedCertificateSecret.getCertificate(), namedCertificateSecret.getPrivateKey());
  }

  @Override
  public String getType() {
    return "certificate";
  }

  public CertificateBody getCertificateBody() {
    return certificateBody;
  }

  public CertificateSecret setCertificateBody(CertificateBody certificateBody) {
    this.certificateBody = certificateBody;
    return this;
  }
}
