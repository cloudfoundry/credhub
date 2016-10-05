package io.pivotal.security.entity;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "RsaSecret")
@DiscriminatorValue("rsa")
public class NamedRsaSecret extends NamedSecret {

  @Column(length = 7000)
  private String publicKey;

  public NamedRsaSecret() {
  }

  public NamedRsaSecret(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public NamedRsaSecret setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public String getPrivateKey() {
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public NamedRsaSecret setPrivateKey(String privateKey) {
    new SecretEncryptionHelper().refreshEncryptedValue(this, privateKey);
    return this;
  }

}
