package io.pivotal.security.entity;

import io.pivotal.security.util.RsaCredentialHelper;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(RsaCredentialVersion.CREDENTIAL_TYPE)
@SecondaryTable(
    name = RsaCredentialVersion.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class RsaCredentialVersion extends CredentialVersion<RsaCredentialVersion> {

  public static final String CREDENTIAL_TYPE = "rsa";
  static final String TABLE_NAME = "rsa_credential";

  @Column(table = RsaCredentialVersion.TABLE_NAME, length = 7000)
  private String publicKey;

  public RsaCredentialVersion() {
    this(null);
  }

  public RsaCredentialVersion(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public RsaCredentialVersion setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Override
  public String getCredentialType() {
    return CREDENTIAL_TYPE;
  }

  public int getKeyLength() {
    final RsaCredentialHelper rsaCredentialHelper = new RsaCredentialHelper(this);
    return rsaCredentialHelper.getKeyLength();
  }
}
