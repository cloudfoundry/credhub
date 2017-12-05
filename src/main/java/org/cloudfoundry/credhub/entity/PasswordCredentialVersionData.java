package org.cloudfoundry.credhub.entity;

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
@DiscriminatorValue(PasswordCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = PasswordCredentialVersionData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class PasswordCredentialVersionData extends CredentialVersionData<PasswordCredentialVersionData> {

  public static final String CREDENTIAL_TYPE = "password";
  static final String TABLE_NAME = "password_credential";

  @OneToOne(cascade = CascadeType.ALL)
  @NotFound(action = NotFoundAction.IGNORE)
  @JoinColumn(table = PasswordCredentialVersionData.TABLE_NAME, name = "password_parameters_uuid")
  private EncryptedValue encryptedGenerationParameters;

  @SuppressWarnings("unused")
  public PasswordCredentialVersionData() {
  }

  public PasswordCredentialVersionData(String name) {
    super(name);
  }


  public PasswordCredentialVersionData setEncryptedGenerationParameters(
     EncryptedValue encryptedGenerationParameters) {
    this.encryptedGenerationParameters = encryptedGenerationParameters;
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
