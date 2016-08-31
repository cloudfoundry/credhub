package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedStringSecret;

import javax.validation.constraints.NotNull;
import java.time.Instant;

public class StringSecret extends Secret {

  @NotNull
  @JsonProperty("value")
  private String value;

  @JsonProperty() // superclass also has this annotation
  private String type;

  public StringSecret(String type, String value) {
    this(null, null, type, value);
  }

  public StringSecret(Instant updatedAt, String uuid, String type) {
    this(updatedAt, uuid, type, null);
  }

  public StringSecret(Instant updatedAt, String uuid, String type, String value) {
    super(updatedAt, uuid);
    if (type == null) {
      throw new IllegalArgumentException("'value' must not be null");
    }
    this.type = type;
    this.value = value;
  }

  public StringSecret(NamedStringSecret namedStringSecret) {
    this(namedStringSecret.getUpdatedAt(), namedStringSecret.getUuid(), namedStringSecret.getSecretType(), namedStringSecret.getValue());
  }

  public StringSecret setValue(String value) {
    this.value = value;
    return this;
  }

  @Override
  public String getType() {
    return this.type;
  }

  public StringSecret setType(String type) {
    this.type = type;
    return this;
  }

  public String getValue() {
    return value;
  }
}