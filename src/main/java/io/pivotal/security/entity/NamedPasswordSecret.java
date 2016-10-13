package io.pivotal.security.entity;

import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.view.SecretKind;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_BYTES;

@Entity
@Table(name = "PasswordSecret")
@DiscriminatorValue("password")
public class NamedPasswordSecret extends NamedStringSecret {

  @Column(length = 255 + NONCE_BYTES)
  private byte[] encryptedGenerationParameters;

  @Column(length = NONCE_BYTES)
  private byte[] parametersNonce;

  @SuppressWarnings("unused")
  public NamedPasswordSecret() {
  }

  public NamedPasswordSecret(String name) {
    super(name);
  }

  public NamedPasswordSecret(String name, String value) {
    super(name, value);
  }

  public NamedPasswordSecret(String name, String value, PasswordGenerationParameters generationParameters) {
    super(name, value);
    setGenerationParameters(generationParameters);
  }

  public byte[] getEncryptedGenerationParameters() {
    return encryptedGenerationParameters;
  }

  public void setEncryptedGenerationParameters(byte[] encryptedGenerationParameters) {
    this.encryptedGenerationParameters = encryptedGenerationParameters;
  }

  public byte[] getParametersNonce() {
    return parametersNonce;
  }

  public void setParametersNonce(byte[] parametersNonce) {
    this.parametersNonce = parametersNonce;
  }

  public PasswordGenerationParameters getGenerationParameters() {
    return SecretEncryptionHelperProvider.getInstance().retrieveGenerationParameters(this);
  }

  public void setGenerationParameters(PasswordGenerationParameters generationParameters) {
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedGenerationParameters(this, generationParameters);
  }

  @Override
  public String getSecretType() {
    return "password";
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.PASSWORD;
  }
}
