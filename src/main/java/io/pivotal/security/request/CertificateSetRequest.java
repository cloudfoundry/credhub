package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import org.codehaus.jackson.annotate.JsonIgnore;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

@SuppressWarnings("unused")
public class CertificateSetRequest extends BaseSecretSetRequest<NamedCertificateSecret> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private CertificateSetRequestFields certificateFields;

  public CertificateSetRequestFields getCertificateFields() {
    return certificateFields;
  }

  public void setCertificateFields(
      CertificateSetRequestFields certificateFields) {
    this.certificateFields = certificateFields;
  }

  @JsonIgnore
  @Override
  public NamedCertificateSecret createNewVersion(NamedCertificateSecret existing, Encryptor encryptor) {
    return NamedCertificateSecret
        .createNewVersion(
            existing,
            getName(),
            getCertificateFields(),
            encryptor,
            getAccessControlEntries());
  }
}
