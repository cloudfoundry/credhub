package io.pivotal.security.entity;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Table;

@Entity
@Table(name = "RsaSecret")
@DiscriminatorValue("rsa")
public class NamedRsaSecret extends NamedRsaSshSecret {
  public NamedRsaSecret() {
    this(null);
  }

  public NamedRsaSecret(String name) {
    super(name);
  }
}
