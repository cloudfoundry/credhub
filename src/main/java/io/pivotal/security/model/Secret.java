package io.pivotal.security.model;

import io.pivotal.security.entity.NamedSecret;

import javax.validation.constraints.NotNull;

public interface Secret<T> {
  String getType();
  @NotNull NamedSecret makeEntity(String name);
  void populateEntity(T entity);
}
