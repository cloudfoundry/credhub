package io.pivotal.security.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.view.SecretKind;
import org.springframework.util.Assert;

import java.io.IOException;

public class NamedPasswordSecret extends NamedSecret<NamedPasswordSecret> {

  private NamedPasswordSecretData delegate;
  private ObjectMapper objectMapper;

  public NamedPasswordSecret(NamedPasswordSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
    this.objectMapper = new ObjectMapper();
  }

  public NamedPasswordSecret(String name) {
    this(new NamedPasswordSecretData(name));
  }

  public NamedPasswordSecret() {
    this(new NamedPasswordSecretData());
  }

  public String getPassword() {
    return encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedValue(),
        delegate.getNonce()
    );
  }

  public NamedPasswordSecret setPasswordAndGenerationParameters(String password, PasswordGenerationParameters generationParameters) {
    if(password == null) {
      throw new IllegalArgumentException("password cannot be null");
    }

    try {
      String generationParameterJson = generationParameters != null ? objectMapper.writeValueAsString(generationParameters) : null;

      Encryption encryptedParameters = encryptor.encrypt(generationParameterJson);
      delegate.setEncryptedGenerationParameters(encryptedParameters.encryptedValue);
      delegate.setParametersNonce(encryptedParameters.nonce);

      Encryption encryptedPassword = encryptor.encrypt(password);
      delegate.setEncryptedValue(encryptedPassword.encryptedValue);
      delegate.setNonce(encryptedPassword.nonce);

      delegate.setEncryptionKeyUuid(encryptor.getActiveUuid());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return this;
  }

  public byte[] getEncryptedGenerationParameters() {
    return delegate.getEncryptedGenerationParameters();
  }

  public NamedPasswordSecret setEncryptedGenerationParameters(byte[] encryptedGenerationParameters) {
    delegate.setEncryptedGenerationParameters(encryptedGenerationParameters);
    return this;
  }

  public byte[] getParametersNonce() {
    return delegate.getParametersNonce();
  }

  public NamedPasswordSecret setParametersNonce(byte[] parametersNonce) {
    delegate.setParametersNonce(parametersNonce);
    return this;
  }

  public PasswordGenerationParameters getGenerationParameters() {
    String password = getPassword();
    Assert.notNull(password, "Password length generation parameter cannot be restored without an existing password");

    String parameterJson = encryptor.decrypt(
        delegate.getEncryptionKeyUuid(),
        delegate.getEncryptedGenerationParameters(),
        delegate.getParametersNonce()
    );
    if (parameterJson == null) {
      return null;
    }

    try {
      PasswordGenerationParameters passwordGenerationParameters = objectMapper.readValue(parameterJson, PasswordGenerationParameters.class);
      passwordGenerationParameters.setLength(password.length());
      return passwordGenerationParameters;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }

  public void rotate(){
    String decryptedPassword = this.getPassword();
    PasswordGenerationParameters decryptedGenerationParameters = this.getGenerationParameters();
    this.setPasswordAndGenerationParameters(decryptedPassword, decryptedGenerationParameters);
  }

  public NamedPasswordSecret createNewVersion(String password) {
    NamedPasswordSecret secret = new NamedPasswordSecret();
    secret.setEncryptor(encryptor);
    secret.setPasswordAndGenerationParameters(password, null);
    secret.delegate.setSecretName(this.delegate.getSecretName());
    return secret;
  }

  public static NamedPasswordSecret createNewVersion(NamedPasswordSecret existing, String name, String password, Encryptor encryptor) {
    if (existing != null) {
      if (!existing.getName().equals(name)) {
        throw new IllegalArgumentException();
      }
      return existing.createNewVersion(password);
    } else {
      NamedPasswordSecret secret = new NamedPasswordSecret(name);
      secret.setEncryptor(encryptor);
      secret.setPasswordAndGenerationParameters(password, null);
      return secret;
    }
  }
}
