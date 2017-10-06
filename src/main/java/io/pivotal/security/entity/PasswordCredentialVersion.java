package io.pivotal.security.entity;

import io.pivotal.security.service.Encryption;
import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;

import javax.persistence.CascadeType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(PasswordCredentialVersion.CREDENTIAL_TYPE)
@SecondaryTable(
    name = PasswordCredentialVersion.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class PasswordCredentialVersion extends CredentialVersion<PasswordCredentialVersion> {

  public static final String CREDENTIAL_TYPE = "password";
  static final String TABLE_NAME = "password_credential";

  @OneToOne(cascade = CascadeType.ALL)
  @NotFound(action = NotFoundAction.IGNORE)
  @JoinColumn(table = PasswordCredentialVersion.TABLE_NAME, name = "password_parameters_uuid")
  private EncryptedValue encryptedGenerationParameters;

  @SuppressWarnings("unused")
  public PasswordCredentialVersion() {
  }

  public PasswordCredentialVersion(String name) {
    super(name);
  }


  public PasswordCredentialVersion setEncryptedGenerationParameters(
     Encryption encryptedGenerationParameters) {
    if (this.encryptedGenerationParameters == null){
      this.encryptedGenerationParameters = new EncryptedValue();
    }
    this.encryptedGenerationParameters.setEncryptedValue(encryptedGenerationParameters.encryptedValue);
    this.encryptedGenerationParameters.setEncryptionKeyUuid(encryptedGenerationParameters.canaryUuid);
    this.encryptedGenerationParameters.setNonce(encryptedGenerationParameters.nonce);
    return this;
  }

  public EncryptedValue getEncryptedGenerationParameters() {
    return encryptedGenerationParameters;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
