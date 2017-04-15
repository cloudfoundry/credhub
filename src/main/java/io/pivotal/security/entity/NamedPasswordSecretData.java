package io.pivotal.security.entity;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(NamedPasswordSecretData.SECRET_TYPE)
@SecondaryTable(
    name = NamedPasswordSecretData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class NamedPasswordSecretData extends NamedSecretData<NamedPasswordSecretData> {

  public static final String SECRET_TYPE = "password";
  static final String TABLE_NAME = "PasswordSecret";
  @Column(table = NamedPasswordSecretData.TABLE_NAME, length = 255 + NONCE_SIZE)
  private byte[] encryptedGenerationParameters;
  @Column(table = NamedPasswordSecretData.TABLE_NAME, length = NONCE_SIZE)
  private byte[] parametersNonce;

  @SuppressWarnings("unused")
  public NamedPasswordSecretData() {
  }

  public NamedPasswordSecretData(String name) {
    super(name);
  }

  public byte[] getEncryptedGenerationParameters() {
    return encryptedGenerationParameters;
  }

  public NamedPasswordSecretData setEncryptedGenerationParameters(
      byte[] encryptedGenerationParameters) {
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

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }
}
