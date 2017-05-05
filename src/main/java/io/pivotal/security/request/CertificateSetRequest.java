package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Encryptor;
import org.codehaus.jackson.annotate.JsonIgnore;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

@SuppressWarnings("unused")
public class CertificateSetRequest extends BaseCredentialSetRequest<CertificateCredential> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private CertificateCredentialValue certificateValue;

  public CertificateCredentialValue getCertificateValue() {
    return certificateValue;
  }

  public void setCertificateValue(
      CertificateCredentialValue certificateValue) {
    this.certificateValue = certificateValue;
  }

  @JsonIgnore
  @Override
  public CertificateCredential createNewVersion(CertificateCredential existing, Encryptor encryptor) {
    return CertificateCredential
        .createNewVersion(
            existing,
            getName(),
            getCertificateValue(),
            encryptor
        );
  }
}
