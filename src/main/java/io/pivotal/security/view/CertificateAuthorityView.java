package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.secret.CertificateAuthority;

import java.util.UUID;

public class CertificateAuthorityView extends BaseView {

  private final String type;
  private final UUID uuid;
  private final CertificateAuthority value;

  public CertificateAuthorityView(NamedCertificateAuthority namedCa) {
    super(namedCa.getVersionCreatedAt());
    this.type = namedCa.getType();
    this.uuid = namedCa.getUuid();
    this.value = new CertificateAuthority(namedCa.getType(), namedCa.getCertificate(), namedCa.getPrivateKey());
  }

  @JsonProperty("type")
  public String getType() {
    return type;
  }

  @JsonProperty("id")
  public String getUuid() {
    return uuid.toString();
  }

  @JsonProperty("value")
  public CertificateAuthority getValue() {
    return value;
  }

  public static CertificateAuthorityView fromEntity(NamedCertificateAuthority namedCertificateAuthority) {
    return new CertificateAuthorityView(namedCertificateAuthority);
  }
}
