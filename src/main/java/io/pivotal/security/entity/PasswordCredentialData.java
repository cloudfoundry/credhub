package io.pivotal.security.entity;

import javax.persistence.*;

import static io.pivotal.security.constants.EncryptionConstants.NONCE_SIZE;

@Entity
@DiscriminatorValue(PasswordCredentialData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = PasswordCredentialData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class PasswordCredentialData extends CredentialData<PasswordCredentialData> {

  public static final String CREDENTIAL_TYPE = "password";
  static final String TABLE_NAME = "PasswordSecret";
  @Column(table = PasswordCredentialData.TABLE_NAME, length = 255 + NONCE_SIZE)
  private byte[] encryptedGenerationParameters;
  @Column(table = PasswordCredentialData.TABLE_NAME, length = NONCE_SIZE)
  private byte[] parametersNonce;

  @SuppressWarnings("unused")
  public PasswordCredentialData() {
  }

  public PasswordCredentialData(String name) {
    super(name);
  }

  public byte[] getEncryptedGenerationParameters() {
    return encryptedGenerationParameters == null ? null : encryptedGenerationParameters.clone();
  }

  public PasswordCredentialData setEncryptedGenerationParameters(
      byte[] encryptedGenerationParameters) {
    this.encryptedGenerationParameters = encryptedGenerationParameters == null ? null : encryptedGenerationParameters.clone();
    return this;
  }

  public byte[] getParametersNonce() {
    return parametersNonce == null ? null : parametersNonce.clone();
  }

  public PasswordCredentialData setParametersNonce(byte[] parametersNonce) {
    this.parametersNonce = parametersNonce == null ? null : parametersNonce.clone();
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
