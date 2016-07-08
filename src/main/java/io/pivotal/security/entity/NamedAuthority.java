package io.pivotal.security.entity;

import io.pivotal.security.view.BaseView;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "NamedAuthority")
@Inheritance(strategy = InheritanceType.JOINED)
@EntityListeners(AuditingEntityListener.class)
@DiscriminatorColumn(name = "type", discriminatorType = DiscriminatorType.STRING)
abstract public class NamedAuthority<T> {
  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  @Column(unique = true, nullable = false)
  private String name;

  @Column(nullable = false)
  @CreatedDate
  @LastModifiedDate
  private LocalDateTime updatedAt;

  public NamedAuthority() {
  }

  public NamedAuthority(String name) {
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

  public abstract BaseView generateView();

  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }

  public T setUpdatedAt(LocalDateTime updatedAt) {
    this.updatedAt = updatedAt;
    return (T) this;
  }
}
