package io.pivotal.security.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.service.EncryptionKeyService;
import io.pivotal.security.service.EncryptionKey;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.Encryption;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.Objects;
import java.util.UUID;

@Component
public class SecretEncryptionHelper {

  private final ObjectMapper objectMapper;

  private final EncryptionKeyService encryptionKeyService;
  private final EncryptionService encryptionService;
  private String clearTextValue;

  @Autowired
  SecretEncryptionHelper(EncryptionKeyService encryptionKeyService, EncryptionService encryptionService) {
    this.encryptionKeyService = encryptionKeyService;
    this.encryptionService = encryptionService;
    this.objectMapper = new ObjectMapper();
  }

  public void refreshEncryptedValue(EncryptedValueContainer encryptedValueContainer, String clearTextValue) {
    UUID activeEncryptionKeyUuid = encryptionKeyService.getActiveEncryptionKeyUuid();

    if (clearTextValue == null) {
      encryptedValueContainer.setNonce(null);
      encryptedValueContainer.setEncryptedValue(null);
      encryptedValueContainer.setEncryptionKeyUuid(activeEncryptionKeyUuid);
      return;
    }
    try {
      EncryptionKey usedEncryptionKey = encryptionKeyService.getEncryptionKey(encryptedValueContainer.getEncryptionKeyUuid());

      if (encryptedValueContainer.getNonce() == null ||
          encryptedValueContainer.getEncryptedValue() == null ||
          encryptedValueContainer.getEncryptionKeyUuid() != activeEncryptionKeyUuid ||
          !Objects.equals(clearTextValue, encryptionService.decrypt(
              usedEncryptionKey, encryptedValueContainer.getEncryptedValue(), encryptedValueContainer.getNonce()
          ))) {
        EncryptionKey activeEncryptionKey = encryptionKeyService.getActiveEncryptionKey();
        final Encryption encryption = encryptionService.encrypt(activeEncryptionKey, clearTextValue);
        encryptedValueContainer.setNonce(encryption.nonce);
        encryptedValueContainer.setEncryptedValue(encryption.encryptedValue);
        encryptedValueContainer.setEncryptionKeyUuid(activeEncryptionKeyUuid);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public String retrieveClearTextValue(EncryptedValueContainer encryptedValueContainer) {
    if (encryptedValueContainer.getNonce() == null || encryptedValueContainer.getEncryptedValue() == null) {
      return null;
    }
    try {
      EncryptionKey encryptionKey = encryptionKeyService.getEncryptionKey(encryptedValueContainer.getEncryptionKeyUuid());
      return encryptionService.decrypt(encryptionKey, encryptedValueContainer.getEncryptedValue(), encryptedValueContainer.getNonce());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void refreshEncryptedGenerationParameters(NamedPasswordSecret namedPasswordSecret, PasswordGenerationParameters generationParameters) {
    try {
      clearTextValue = generationParameters != null ? objectMapper.writeValueAsString(generationParameters) : null;
      refreshEncryptedValue(new ParametersAdapter(namedPasswordSecret), clearTextValue);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public PasswordGenerationParameters retrieveGenerationParameters(NamedPasswordSecret namedPasswordSecret) {
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

  private static class ParametersAdapter implements EncryptedValueContainer {
    private final NamedPasswordSecret namedPasswordSecret;

    ParametersAdapter(NamedPasswordSecret namedPasswordSecret) {
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
      return namedPasswordSecret.getParameterEncryptionKeyUuid();
    }

    @Override
    public void setEncryptionKeyUuid(UUID encryptionKeyUuid) {
      namedPasswordSecret.setParameterEncryptionKeyUuid(encryptionKeyUuid);
    }
  }
}
