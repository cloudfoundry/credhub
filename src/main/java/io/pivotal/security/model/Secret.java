package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public interface Secret<T> {
  @JsonProperty String getType();
  void populateEntity(T entity);
}
