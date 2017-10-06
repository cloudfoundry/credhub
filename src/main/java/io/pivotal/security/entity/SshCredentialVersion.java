package io.pivotal.security.entity;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(SshCredentialVersion.CREDENTIAL_TYPE)
@SecondaryTable(
    name = SshCredentialVersion.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)

public class SshCredentialVersion extends CredentialVersion<SshCredentialVersion> {

  public static final String CREDENTIAL_TYPE = "ssh";
  static final String TABLE_NAME = "ssh_credential";

  @Column(table = SshCredentialVersion.TABLE_NAME, length = 7000)
  private String publicKey;

  public SshCredentialVersion() {
    this(null);
  }

  public SshCredentialVersion(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public SshCredentialVersion setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
