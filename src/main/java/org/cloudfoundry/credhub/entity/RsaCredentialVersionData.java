package org.cloudfoundry.credhub.entity;

import org.cloudfoundry.credhub.util.RsaCredentialHelper;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(RsaCredentialVersionData.CREDENTIAL_TYPE)
@SecondaryTable(
    name = RsaCredentialVersionData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class RsaCredentialVersionData extends CredentialVersionData<RsaCredentialVersionData> {

  public static final String CREDENTIAL_TYPE = "rsa";
  static final String TABLE_NAME = "rsa_credential";

  @Column(table = RsaCredentialVersionData.TABLE_NAME, length = 7000)
  private String publicKey;

  public RsaCredentialVersionData() {
    this(null);
  }

  public RsaCredentialVersionData(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public RsaCredentialVersionData setPublicKey(String publicKey) {
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
