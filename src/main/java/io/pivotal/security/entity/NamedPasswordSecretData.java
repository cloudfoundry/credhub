package io.pivotal.security.entity;

import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.view.SecretKind;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

@Entity
@Table(name = "PasswordSecret")
@DiscriminatorValue(NamedPasswordSecretData.SECRET_TYPE)
public class NamedPasswordSecretData extends NamedStringSecretData<NamedPasswordSecretData> {

  @Column(length = 255 + NONCE_SIZE)
  private byte[] encryptedGenerationParameters;

  @Column(length = NONCE_SIZE)
  private byte[] parametersNonce;

  public static final String SECRET_TYPE = "password";

  @SuppressWarnings("unused")
  public NamedPasswordSecretData() {
  }

  public NamedPasswordSecretData(String name) {
    super(name);
  }

  public byte[] getEncryptedGenerationParameters() {
    return encryptedGenerationParameters;
  }

  public NamedPasswordSecretData setEncryptedGenerationParameters(byte[] encryptedGenerationParameters) {
    this.encryptedGenerationParameters = encryptedGenerationParameters;
    return this;
  }

  public byte[] getParametersNonce() {
    return parametersNonce;
  }

  public NamedPasswordSecretData setParametersNonce(byte[] parametersNonce) {
    this.parametersNonce = parametersNonce;
    return this;
  }

  public PasswordGenerationParameters getGenerationParameters() {
    return SecretEncryptionHelperProvider.getInstance().retrieveGenerationParameters(this);
  }

  public NamedPasswordSecretData setGenerationParameters(PasswordGenerationParameters generationParameters) {
    SecretEncryptionHelperProvider.getInstance().refreshEncryptedGenerationParameters(this, generationParameters);
    return this;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  @Override
  public void copyIntoImpl(NamedPasswordSecretData copy) {
    copy.setEncryptedGenerationParameters(encryptedGenerationParameters);
    copy.setParametersNonce(parametersNonce);
  }

  @Override
  public SecretKind getKind() {
    return SecretKind.PASSWORD;
  }
}
