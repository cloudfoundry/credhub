package io.pivotal.security.credential;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.pivotal.security.util.EmptyStringToNull;
import io.pivotal.security.validator.MutuallyExclusive;
import io.pivotal.security.validator.RequireAnyOf;

@RequireAnyOf(message = "error.missing_certificate_credentials", fields = {"ca", "certificate", "privateKey"})
@MutuallyExclusive(message = "error.mixed_ca_name_and_ca", fields = {"ca", "caName"})
public class CertificateCredentialValue implements CredentialValue {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String ca;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String certificate;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
  @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
  private String caName;

  @SuppressWarnings("unused")
  public CertificateCredentialValue() {}

  public CertificateCredentialValue(
      String ca,
      String certificate,
      String privateKey,
      String caName
  ) {
    this.ca = ca;
    this.certificate = certificate;
    this.privateKey = privateKey;
    this.caName = caName;
  }

  public String getCa() {
    return ca;
  }

  public String getCertificate() {
    return certificate;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public String getCaName() {
    return caName;
  }
}
