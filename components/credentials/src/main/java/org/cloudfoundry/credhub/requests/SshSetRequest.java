package org.cloudfoundry.credhub.requests;

import java.util.Objects;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.SshCredentialValue;

public class SshSetRequest extends BaseCredentialSetRequest<SshCredentialValue> {

  @NotNull(message = ErrorMessages.MISSING_VALUE)
  @Valid
  @JsonProperty("value")
  private SshCredentialValue sshKeyValue;

  public SshCredentialValue getSshKeyValue() {
    return sshKeyValue;
  }

  public void setSshKeyValue(final SshCredentialValue sshKeyValue) {
    this.sshKeyValue = sshKeyValue;
  }

  @Override
  public SshCredentialValue getCredentialValue() {
    return sshKeyValue;
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final SshSetRequest that = (SshSetRequest) o;
    return Objects.equals(sshKeyValue, that.sshKeyValue);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sshKeyValue);
  }
}
