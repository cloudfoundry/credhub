package org.cloudfoundry.credhub.requests;

import java.util.Objects;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.StringCredentialValue;

public class PasswordSetRequest extends BaseCredentialSetRequest<StringCredentialValue> {

  @NotNull(message = ErrorMessages.MISSING_VALUE)
  @Valid
  @JsonProperty("value")
  private StringCredentialValue password;
  @JsonIgnore
  private StringGenerationParameters generationParameters;

  public StringCredentialValue getPassword() {
    return password;
  }

  public void setPassword(final StringCredentialValue password) {
    this.password = password;
  }

  @Override
  public StringGenerationParameters getGenerationParameters() {
    return generationParameters;
  }

  public void setGenerationParameters(final StringGenerationParameters generationParameters) {
    this.generationParameters = generationParameters;
  }

  @Override
  public StringCredentialValue getCredentialValue() {
    return password;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    final PasswordSetRequest that = (PasswordSetRequest) o;
    return Objects.equals(password, that.password) &&
      Objects.equals(generationParameters, that.generationParameters);
  }

  @Override
  public int hashCode() {
    return Objects.hash(password, generationParameters);
  }
}
