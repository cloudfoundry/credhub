package org.cloudfoundry.credhub.entity;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(SshCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(
  name = SshCredentialVersionData.TABLE_NAME,
  pkJoinColumns = @PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")
)

public class SshCredentialVersionData extends CredentialVersionData<SshCredentialVersionData> {

  public static final String CREDENTIAL_TYPE = "ssh";
  public static final String TABLE_NAME = "ssh_credential";

  @Column(table = SshCredentialVersionData.TABLE_NAME, length = 7000)
  private String publicKey;

  public SshCredentialVersionData() {
    this(null);
  }

  public SshCredentialVersionData(final String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(final String publicKey) {
    this.publicKey = publicKey;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }
}
