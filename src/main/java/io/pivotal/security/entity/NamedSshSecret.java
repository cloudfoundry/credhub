package io.pivotal.security.entity;

import javax.persistence.*;

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
}
