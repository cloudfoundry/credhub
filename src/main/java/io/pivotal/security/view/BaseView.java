package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public abstract class BaseView<ET, T> {
  private Instant updatedAt;

  public abstract void populateEntity(ET entity);

  public abstract BaseView generateView(ET entity);

  @JsonProperty("updated_at")
  public Instant getUpdatedAt() {
    return updatedAt;
  }

  public T setUpdatedAt(Instant updatedAt) {
    this.updatedAt = updatedAt;
    return (T) this;
  }
}
