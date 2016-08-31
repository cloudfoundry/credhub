package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;

import java.time.Instant;

public class CertificateAuthority extends BaseView {

  @JsonProperty("type")
  private String type;

  @JsonProperty("value")
  private CertificateAuthorityBody certificateAuthorityBody;

  public CertificateAuthority(String type, String certificate, String privateKey) {
    this(null, type, certificate, privateKey);
  }

  public CertificateAuthority(Instant updatedAt, String type, String certificate, String privateKey) {
    super(updatedAt);
    setType(type);
    setCertificateBody(new CertificateAuthorityBody(certificate, privateKey));
  }

  public CertificateAuthority(NamedCertificateAuthority namedCertificateAuthority) {
    this(namedCertificateAuthority.getUpdatedAt(), namedCertificateAuthority.getType(), namedCertificateAuthority.getCertificate(), namedCertificateAuthority.getPrivateKey());
  }

  public CertificateAuthorityBody getCertificateAuthorityBody() {
    return certificateAuthorityBody;
  }

  public CertificateAuthority setCertificateBody(CertificateAuthorityBody certificateAuthorityBody) {
    this.certificateAuthorityBody = certificateAuthorityBody;
    return this;
  }

  public CertificateAuthority setType(String type) {
    this.type = type;
    return this;
  }

  public String getType() {
    return type;
  }

  public static CertificateAuthority fromEntity(NamedCertificateAuthority namedCertificateAuthority) {
    return new CertificateAuthority(namedCertificateAuthority);
  }
}