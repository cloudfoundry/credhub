package io.pivotal.security.entity;

import io.pivotal.security.util.NamedRsaSecretHelper;
import io.pivotal.security.view.SecretKind;
import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.SecondaryTable;

@Entity
@DiscriminatorValue(NamedRsaSecretData.SECRET_TYPE)
@SecondaryTable(
    name = NamedRsaSecretData.TABLE_NAME,
    pkJoinColumns = {@PrimaryKeyJoinColumn(name = "uuid", referencedColumnName = "uuid")}
)
public class NamedRsaSecretData extends NamedSecretData<NamedRsaSecretData> {

  public static final String SECRET_TYPE = "rsa";
  static final String TABLE_NAME = "RsaSecret";
  @Column(table = NamedRsaSecretData.TABLE_NAME, length = 7000)
  private String publicKey;

  public NamedRsaSecretData() {
    this(null);
  }

  public NamedRsaSecretData(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public NamedRsaSecretData setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  @Override
  public void copyIntoImpl(NamedRsaSecretData copy) {
    copy.setPublicKey(getPublicKey());
  }

  public SecretKind getKind() {
    return SecretKind.RSA;
  }

  @Override
  public String getSecretType() {
    return SECRET_TYPE;
  }

  public int getKeyLength() {
    final NamedRsaSecretHelper namedRsaSecretHelper = new NamedRsaSecretHelper(this);
    return namedRsaSecretHelper.getKeyLength();
  }
}
