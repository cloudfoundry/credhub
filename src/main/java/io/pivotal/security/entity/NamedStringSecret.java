package io.pivotal.security.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class NamedStringSecret {

  @Id
  @GeneratedValue(strategy = javax.persistence.GenerationType.AUTO)
  public long id;

  @Column(unique = true, nullable = false)
  public String name;

  @Column(nullable = false)
  public String value;
}