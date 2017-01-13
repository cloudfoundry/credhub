package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;

import java.time.Instant;
import java.util.UUID;

public class CertificateAuthority extends BaseView {

  @JsonProperty("type")
  private String type;

  @JsonProperty("value")
  private CertificateAuthorityBody certificateAuthorityBody;
  private UUID uuid;

  public CertificateAuthority(String type, String certificate, String privateKey) {
    this(null, type, certificate, privateKey, null);
  }

  public CertificateAuthority(Instant versionCreatedAt,
                              String type,
                              String certificate,
                              String privateKey,
                              UUID uuid) {
    super(versionCreatedAt);
    setType(type);
    setCertificateBody(new CertificateAuthorityBody(certificate, privateKey));
    setUuid(uuid);
  }

  public CertificateAuthority(NamedCertificateAuthority namedCa) {
    this(namedCa.getVersionCreatedAt(),
        namedCa.getType(),
        namedCa.getCertificate(),
        namedCa.getPrivateKey(),
        namedCa.getUuid());
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

  @JsonProperty("id")
  public String getUuid() {
    return uuid.toString();
  }

  public void setUuid(UUID uuid) {
    this.uuid = uuid;
  }

  public static CertificateAuthority fromEntity(NamedCertificateAuthority namedCertificateAuthority) {
    return new CertificateAuthority(namedCertificateAuthority);
  }
}
