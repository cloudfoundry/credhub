package io.pivotal.security.entity;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(SshCredentialData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = SshCredentialData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)

public class SshCredentialData extends CredentialData<SshCredentialData> {

  public static final String CREDENTIAL_TYPE = "ssh";
  static final String TABLE_NAME = "ssh_credential";

  @Column(table = SshCredentialData.TABLE_NAME, length = 7000)
  private String publicKey;

  public SshCredentialData() {
    this(null);
  }

  public SshCredentialData(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public SshCredentialData setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
