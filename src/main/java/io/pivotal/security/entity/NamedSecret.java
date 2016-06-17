package io.pivotal.security.entity;

import io.pivotal.security.model.Secret;

import javax.persistence.*;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@DiscriminatorColumn(name="type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecret<T> {
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

  public T setId(long id) {
    this.id = id;
    return (T) this;
  }

  public String getName() {
    return name;
  }

  public T setName(String name) {
    this.name = name;
    return (T) this;
  }

  public abstract Secret convertToModel();
}
