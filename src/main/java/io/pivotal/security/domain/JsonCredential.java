package io.pivotal.security.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.pivotal.security.credential.JsonCredentialValue;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.JsonObjectMapper;

import java.io.IOException;
import java.util.Map;

public class JsonCredential extends Credential<JsonCredential> {

  private final JsonObjectMapper objectMapper;
  private final JsonCredentialData delegate;

  public JsonCredential() {
    this(new JsonCredentialData());
  }

  public JsonCredential(JsonCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
    /*
    It is alright to use a "new" ObjectMapper here because the JSON data does
    not have properties that is maps to, thereby not facing a problem with the
    casing being defined. Using JsonObjectMapper for consistency across project.
     */
    this.objectMapper = new JsonObjectMapper();
  }

  public JsonCredential(String name) {
    this(new JsonCredentialData(name));
  }

  public JsonCredential(JsonCredentialValue jsonValue, Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setValue(jsonValue.getValue());
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    Map<String, Object> value = this.getValue();
    this.setValue(value);
  }

  public Map<String, Object> getValue() {
    String serializedValue = encryptor.decrypt(new Encryption(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()));
    try {
      return objectMapper.readValue(serializedValue, Map.class);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public JsonCredential setValue(Map<String, Object> value) {
    if (value == null) {
      throw new ParameterizedValidationException("error.missing_value");
    }

    try {
      String serializedString = objectMapper.writeValueAsString(value);
      Encryption encryption = encryptor.encrypt(serializedString);

      delegate.setEncryptedValue(encryption.encryptedValue);
      delegate.setNonce(encryption.nonce);
      delegate.setEncryptionKeyUuid(encryption.canaryUuid);
      return this;
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }
}
