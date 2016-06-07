package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@DiscriminatorColumn(name="type", discriminatorType = DiscriminatorType.STRING)
public class NamedSecret {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  public long id;
  @Column(unique = true, nullable = false)
  public String name;

  public NamedSecret() {
  }

  public NamedSecret(String name) {
    this.name = name;
  }
}
