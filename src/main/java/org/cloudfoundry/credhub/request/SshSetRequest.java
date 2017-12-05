package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.credential.SshCredentialValue;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class SshSetRequest extends BaseCredentialSetRequest<SshCredentialValue> {

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
  public SshCredentialValue getCredentialValue() {
    return sshKeyValue;
  }
}
