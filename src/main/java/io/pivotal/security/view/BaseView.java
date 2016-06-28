package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;

public abstract class BaseView<ET, T> {
  private LocalDateTime updatedAt;

  public abstract void populateEntity(ET entity);

  @JsonProperty("updated_at")
  public LocalDateTime getUpdatedAt() {
    return updatedAt;
  }

  public T setUpdatedAt(LocalDateTime updatedAt) {
    this.updatedAt = updatedAt;
    return (T) this;
  }
}
