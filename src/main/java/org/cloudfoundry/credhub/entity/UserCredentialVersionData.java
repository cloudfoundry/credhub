package org.cloudfoundry.credhub.entity;

import org.hibernate.annotations.NotFound;
import org.hibernate.annotations.NotFoundAction;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.OneToOne;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue("user")
@SecondaryTable(
    name = UserCredentialVersionData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class UserCredentialVersionData extends CredentialVersionData<UserCredentialVersionData> {
  public static final String TABLE_NAME = "user_credential";
  public static final String CREDENTIAL_TYPE = "user";

  @Column(table = UserCredentialVersionData.TABLE_NAME, length = 7000)
  private String username;

  @Column(table = UserCredentialVersionData.TABLE_NAME, length = 20)
  private String salt;

  @OneToOne(cascade = CascadeType.ALL)
  @NotFound(action = NotFoundAction.IGNORE)
  @JoinColumn(table = UserCredentialVersionData.TABLE_NAME, name = "password_parameters_uuid")
  private EncryptedValue encryptedGenerationParameters;

  public UserCredentialVersionData() {
    this(null);
  }

  public UserCredentialVersionData(String name) {
    super(name);
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }

  public String getUsername() {
    return username;
  }

  public UserCredentialVersionData setUsername(String username) {
    this.username = username;
    return this;
  }

  public UserCredentialVersionData setSalt(String salt) {
    this.salt = salt;
    return this;
  }

  public String getSalt() {
    return salt;
  }

  public UserCredentialVersionData setEncryptedGenerationParameters(EncryptedValue encryptedGenerationParameters) {
    this.encryptedGenerationParameters = encryptedGenerationParameters;
    return this;
  }

  public EncryptedValue getEncryptedGenerationParameters() {
    return encryptedGenerationParameters;
  }
}
