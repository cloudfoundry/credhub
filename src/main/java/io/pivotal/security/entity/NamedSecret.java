package io.pivotal.security.entity;

import javax.persistence.*;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@DiscriminatorColumn(name="type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecret {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;
  @Column(unique = true, nullable = false)
  private String name;

  public NamedSecret() {
  }

  public NamedSecret(String name) {
    this.setName(name);
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public abstract Object convertToModel();
}
