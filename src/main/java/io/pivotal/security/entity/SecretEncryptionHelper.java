package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.RetryingEncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.UUID;

@Component
public class SecretEncryptionHelper {

  private final ObjectMapper objectMapper;

  private final EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private final RetryingEncryptionService encryptionService;

  @Autowired
  SecretEncryptionHelper(EncryptionKeyCanaryMapper encryptionKeyCanaryMapper, RetryingEncryptionService encryptionService) {
    this.encryptionKeyCanaryMapper = encryptionKeyCanaryMapper;
    this.encryptionService = encryptionService;
    this.objectMapper = new ObjectMapper();
  }

  public void refreshEncryptedValue(EncryptedValueContainer encryptedValueContainer, String clearTextValue) {
    UUID activeEncryptionKeyUuid = encryptionKeyCanaryMapper.getActiveUuid();

    if (clearTextValue == null) {
      encryptedValueContainer.setNonce(null);
      encryptedValueContainer.setEncryptedValue(null);
    } else {
      try {
        encrypt(encryptedValueContainer, clearTextValue);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    encryptedValueContainer.setEncryptionKeyUuid(activeEncryptionKeyUuid);
  }

  public String retrieveClearTextValue(EncryptedValueContainer encryptedValueContainer) {
    if (encryptedValueContainer.getNonce() == null || encryptedValueContainer.getEncryptedValue() == null) {
      return null;
    }
    return decrypt(encryptedValueContainer);
  }

  public void refreshEncryptedGenerationParameters(NamedPasswordSecretData namedPasswordSecret, PasswordGenerationParameters generationParameters) {
    try {
      String clearTextValue = generationParameters != null ? objectMapper.writeValueAsString(generationParameters) : null;
      refreshEncryptedValue(new ParametersAdapter(namedPasswordSecret), clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public PasswordGenerationParameters retrieveGenerationParameters(NamedPasswordSecretData namedPasswordSecret) {
    String password = retrieveClearTextValue(namedPasswordSecret);
    Assert.notNull(password, "Password length generation parameter cannot be restored without an existing password");
    String json = retrieveClearTextValue(new ParametersAdapter(namedPasswordSecret));
    if (json == null) {
      return null;
    }
    try {
      return objectMapper.readValue(json, PasswordGenerationParameters.class).setLength(password.length());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public void rotate(EncryptedValueContainer secret) {
    if (usingOldEncryptionKey(secret)) {
      if (secret instanceof NamedPasswordSecretData) {
        rotatePasswordParameters((NamedPasswordSecretData) secret);
      }

      if (secret.getEncryptedValue() != null) {
        try {
          encrypt(secret, decrypt(secret));
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }
    }

    secret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
  }

  private boolean usingOldEncryptionKey(EncryptedValueContainer secret) {
    final UUID activeEncryptionKeyUuid = encryptionKeyCanaryMapper.getActiveUuid();
    return !activeEncryptionKeyUuid.equals(secret.getEncryptionKeyUuid());
  }

  private void rotatePasswordParameters(NamedPasswordSecretData password) {
    refreshEncryptedGenerationParameters(password, retrieveGenerationParameters(password));
  }

  private void encrypt(EncryptedValueContainer encryptedValueContainer, String clearTextValue) throws Exception {
    final Encryption encryption = encryptionService.encrypt(encryptionKeyCanaryMapper.getActiveUuid(), clearTextValue);
    encryptedValueContainer.setNonce(encryption.nonce);
    encryptedValueContainer.setEncryptedValue(encryption.encryptedValue);
  }

  private String decrypt(EncryptedValueContainer encryptedValueContainer) {
    try {
      return encryptionService.decrypt(encryptedValueContainer.getEncryptionKeyUuid(), encryptedValueContainer.getEncryptedValue(), encryptedValueContainer.getNonce());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static class ParametersAdapter implements EncryptedValueContainer {
    private final NamedPasswordSecretData namedPasswordSecret;

    ParametersAdapter(NamedPasswordSecretData namedPasswordSecret) {
      this.namedPasswordSecret = namedPasswordSecret;
    }

    @Override
    public byte[] getEncryptedValue() {
      return namedPasswordSecret.getEncryptedGenerationParameters();
    }

    @Override
    public void setEncryptedValue(byte[] encryptedValue) {
      namedPasswordSecret.setEncryptedGenerationParameters(encryptedValue);
    }

    @Override
    public byte[] getNonce() {
      return namedPasswordSecret.getParametersNonce();
    }

    @Override
    public void setNonce(byte[] nonce) {
      namedPasswordSecret.setParametersNonce(nonce);
    }

    @Override
    public UUID getEncryptionKeyUuid() {
      return namedPasswordSecret.getEncryptionKeyUuid();
    }

    @Override
    public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
    }
  }
}
