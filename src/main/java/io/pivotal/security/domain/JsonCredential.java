package io.pivotal.security.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.NamedJsonSecretData;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.service.Encryption;

import java.io.IOException;
import java.util.List;
import java.util.Map;

public class JsonCredential extends Credential<JsonCredential> {

  private final ObjectMapper objectMapper;
  private final NamedJsonSecretData delegate;

  public JsonCredential() {
    this(new NamedJsonSecretData());
  }

  public JsonCredential(NamedJsonSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
    this.objectMapper = new ObjectMapper();
  }

  public JsonCredential(String name) {
    this(new NamedJsonSecretData(name));
  }

  public static JsonCredential createNewVersion(
      JsonCredential existing,
      String name,
      Map<String, Object> value,
      Encryptor encryptor,
      List<AccessControlEntry> accessControlEntries
  ) {
    JsonCredential secret;

    if (existing == null) {
      secret = new JsonCredential(name);
    } else {
      secret = new JsonCredential();
      secret.copyNameReferenceFrom(existing);
    }

    secret.setAccessControlList(accessControlEntries);
    secret.setEncryptor(encryptor);
    secret.setValue(value);

    return secret;
  }


  @Override
  public String getSecretType() {
    return delegate.getSecretType();
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
