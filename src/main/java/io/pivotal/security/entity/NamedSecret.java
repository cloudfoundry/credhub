package io.pivotal.security.entity;

import io.pivotal.security.view.Secret;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "NamedSecret")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name="type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedSecret<T> {
  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(nullable = false)
  @CreatedDate
  @LastModifiedDate
  private LocalDateTime updatedAt;

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

  public abstract Secret generateView();

  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }

  public T setUpdatedAt(LocalDateTime updatedAt) {
    this.updatedAt = updatedAt;
    return (T) this;
  }
}
