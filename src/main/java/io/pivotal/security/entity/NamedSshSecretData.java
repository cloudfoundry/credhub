package io.pivotal.security.entity;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(NamedSshSecretData.SECRET_TYPE)
@SecondaryTable(
    name = NamedSshSecretData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)

public class NamedSshSecretData extends NamedSecretData<NamedSshSecretData> {

  public static final String SECRET_TYPE = "ssh";
  static final String TABLE_NAME = "SshSecret";

  @Column(table = NamedSshSecretData.TABLE_NAME, length = 7000)
  private String publicKey;

  public NamedSshSecretData() {
    this(null);
  }

  public NamedSshSecretData(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public NamedSshSecretData setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }
}
