package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.credential.SshCredentialValue;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.SshCredential;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class SshSetRequest extends BaseCredentialSetRequest<SshCredential> {

  @NotNull(message = "error.missing_value")
  @Valid
  @JsonProperty("value")
  private SshCredentialValue sshKeyValue;

  public SshCredentialValue getSshKeyValue() {
    return sshKeyValue;
  }

  public void setSshKeyValue(SshCredentialValue sshKeyValue) {
    this.sshKeyValue = sshKeyValue;
  }

  @Override
  public SshCredential createNewVersion(SshCredential existing, Encryptor encryptor) {
    return SshCredential
        .createNewVersion(existing, getName(), this.getSshKeyValue(),
            encryptor);
  }
}
