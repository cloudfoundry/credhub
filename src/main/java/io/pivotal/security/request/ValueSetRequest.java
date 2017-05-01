package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.ValueCredential;
import org.hibernate.validator.constraints.NotEmpty;

public class ValueSetRequest extends BaseCredentialSetRequest<ValueCredential> {

  @NotEmpty(message = "error.missing_value")
  private String value;

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public ValueCredential createNewVersion(ValueCredential existing, Encryptor encryptor) {
    return ValueCredential
        .createNewVersion(existing, getName(), this.getValue(), encryptor);
  }
}
