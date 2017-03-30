package io.pivotal.security.request;


import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedSecret;
import org.codehaus.jackson.annotate.JsonIgnore;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

@SuppressWarnings("unused")
public class CertificateSetRequest extends BaseSecretSetRequest {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private CertificateSetRequestFields certificateFields;

  public CertificateSetRequestFields getCertificateFields() {
    return certificateFields;
  }

  @JsonIgnore
  @Override
  public NamedSecret createNewVersion(NamedSecret existing, Encryptor encryptor) {
    return NamedCertificateSecret
        .createNewVersion((NamedCertificateSecret) existing, getName(), this.getCertificateFields(),
            encryptor, this.getAccessControlEntries());
  }
}
