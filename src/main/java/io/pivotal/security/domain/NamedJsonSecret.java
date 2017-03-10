package io.pivotal.security.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.entity.NamedJsonSecretData;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.view.SecretKind;

import java.io.IOException;
import java.util.Map;

public class NamedJsonSecret extends NamedSecret<NamedJsonSecret> {
  private final ObjectMapper objectMapper;
  private final NamedJsonSecretData delegate;

  public NamedJsonSecret() {
    this(new NamedJsonSecretData());
  }

  public NamedJsonSecret(NamedJsonSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
    this.objectMapper = new ObjectMapper();
  }

  public NamedJsonSecret(String name) {
    this(new NamedJsonSecretData(name));
  }

  @Override
  public SecretKind getKind() {
    throw new UnsupportedOperationException();
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

  public void setValue(Map<String, Object> value) {
    if (value == null) {
      throw new ParameterizedValidationException("error.missing_value");
    }

    try {
      String serializedString = objectMapper.writeValueAsString(value);
      Encryption encryption = encryptor.encrypt(serializedString);

      delegate.setEncryptedValue(encryption.encryptedValue);
      delegate.setNonce(encryption.nonce);
      delegate.setEncryptionKeyUuid(encryptor.getActiveUuid());
    } catch (JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  public static NamedJsonSecret createNewVersion(NamedJsonSecret existing, String name, Map<String, Object> value, Encryptor encryptor) {
    NamedJsonSecret secret;

    if (existing == null) {
      secret = new NamedJsonSecret(name);
    } else {
      secret = new NamedJsonSecret();
      secret.copyNameReferenceFrom(existing);
    }

    secret.setEncryptor(encryptor);
    secret.setValue(value);

    return secret;
  }
}
