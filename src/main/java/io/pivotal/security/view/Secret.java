package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedSecret;

public abstract class Secret<ET extends NamedSecret, T extends Secret> extends BaseView<ET, T> {
  @JsonProperty
  public abstract String getType();

  private String uuid;

  @JsonProperty("id")
  public String getUuid() {
    return uuid;
  }

  public T setUuid(String uuid) {
    this.uuid = uuid;
    return (T) this;
  }

  @Override
  public T generateView(ET entity) {
    return (T) this
        .setUpdatedAt(entity.getUpdatedAt())
        .setUuid(entity.getUuid());
  }
}