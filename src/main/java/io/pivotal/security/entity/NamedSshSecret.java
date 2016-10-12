package io.pivotal.security.entity;

import io.pivotal.security.view.SecretKind;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "SshSecret")
@DiscriminatorValue("ssh")
public class NamedSshSecret extends NamedRsaSshSecret {
  public NamedSshSecret() {
    this(null);
  }

  public NamedSshSecret(String name) {
    super(name);
  }

  public SecretKind getKind() {
    return SecretKind.SSH;
  }
}
