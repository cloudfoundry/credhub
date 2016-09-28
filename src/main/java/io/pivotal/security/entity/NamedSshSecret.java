package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@Table(name = "SshSecret")
@DiscriminatorValue("ssh")
public class NamedSshSecret extends NamedSecret {

  @Column(length = 7000)
  private String publicKey;

  public NamedSshSecret() {
  }

  public NamedSshSecret(String name) {
    super(name);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public NamedSshSecret setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public String getPrivateKey() {
    return new SecretEncryptionHelper().retrieveClearTextValue(this);
  }

  public NamedSshSecret setPrivateKey(String privateKey) {
    new SecretEncryptionHelper().refreshEncryptedValue(this, privateKey);
    return this;
  }

}
