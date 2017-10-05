package io.pivotal.security.entity;

import io.pivotal.security.service.Encryption;
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
    name = UserCredentialData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class UserCredentialData extends CredentialData<UserCredentialData> {
  public static final String TABLE_NAME = "user_credential";
  public static final String CREDENTIAL_TYPE = "user";

  @Column(table = UserCredentialData.TABLE_NAME, length = 7000)
  private String username;

  @Column(table = UserCredentialData.TABLE_NAME, length = 20)
  private String salt;

  @OneToOne(cascade = CascadeType.ALL)
  @NotFound(action = NotFoundAction.IGNORE)
  @JoinColumn(table = UserCredentialData.TABLE_NAME, name = "password_parameters_uuid")
  private EncryptedValue encryptedGenerationParameters;

  public UserCredentialData() {
    this(null);
  }

  public UserCredentialData(String name) {
    super(name);
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }

  public String getUsername() {
    return username;
  }

  public UserCredentialData setUsername(String username) {
    this.username = username;
    return this;
  }

  public UserCredentialData setSalt(String salt) {
    this.salt = salt;
    return this;
  }

  public String getSalt() {
    return salt;
  }

  public UserCredentialData setEncryptedGenerationParameters(
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
}
