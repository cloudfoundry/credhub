package io.pivotal.security.request;

import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.JsonCredential;
import org.hibernate.validator.constraints.NotEmpty;

import java.util.Map;

public class JsonSetRequest extends BaseCredentialSetRequest<JsonCredential> {

  @NotEmpty(message = "error.missing_value")
  private Map<String, Object> value;

  public Map<String, Object> getValue() {
    return value;
  }

  public void setValue(Map<String, Object> value) {
    this.value = value;
  }

  @Override
  public JsonCredential createNewVersion(JsonCredential existing, Encryptor encryptor) {
    return JsonCredential.createNewVersion(
        existing,
        this.getName(),
        this.getValue(),
        encryptor,
        this.getAccessControlEntries());
  }
}
