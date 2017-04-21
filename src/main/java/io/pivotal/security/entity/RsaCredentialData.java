package io.pivotal.security.entity;

import io.pivotal.security.util.RsaCredentialHelper;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(RsaCredentialData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = RsaCredentialData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class RsaCredentialData extends CredentialData<RsaCredentialData> {

  public static final String CREDENTIAL_TYPE = "rsa";
  static final String TABLE_NAME = "RsaCredential";

  @Column(table = RsaCredentialData.TABLE_NAME, length = 7000)
  private String publicKey;

  public RsaCredentialData() {
    this(null);
  }

  public RsaCredentialData(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public RsaCredentialData setPublicKey(String publicKey) {
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
