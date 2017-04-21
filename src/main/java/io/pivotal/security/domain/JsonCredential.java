package io.pivotal.security.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.JsonCredentialData;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.Encryption;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JsonCredential extends Credential<JsonCredential> {

  private final ObjectMapper objectMapper;
  private final JsonCredentialData delegate;

  public JsonCredential() {
    this(new JsonCredentialData());
  }

  public JsonCredential(JsonCredentialData delegate) {
    super(delegate);
    this.delegate = delegate;
    this.objectMapper = new ObjectMapper();
  }

  public JsonCredential(String name) {
    this(new JsonCredentialData(name));
  }

  public static JsonCredential createNewVersion(
      JsonCredential existing,
      String name,
      Map<String, Object> value,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    JsonCredential credential;

    if (existing == null) {
      credential = new JsonCredential(name);
    } else {
      credential = new JsonCredential();
      credential.copyNameReferenceFrom(existing);
    }

    credential.setAccessControlList(accessControlEntries);
    credential.setEncryptor(encryptor);
    credential.setValue(value);

    return credential;
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
    String serializedValue = encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()
    );
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
