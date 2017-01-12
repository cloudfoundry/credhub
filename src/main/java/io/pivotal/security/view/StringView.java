package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedStringSecret;

import javax.validation.constraints.NotNull;
import java.time.Instant;
import java.util.UUID;

public class StringView extends SecretView {

  @NotNull
  @JsonProperty("value")
  private String value;

  @JsonProperty() // superclass also has this annotation
  private String type;

  public StringView(String type, String value) {
    this(null, null, null, type, value);
  }

  public StringView(Instant versionCreatedAt, UUID uuid, String name, String type, String value) {
    super(versionCreatedAt, uuid, name);
    if (type == null) {
      throw new IllegalArgumentException("'value' must not be null");
    }
    this.type = type;
    this.value = value;
  }

  public StringView(NamedStringSecret namedStringSecret) {
    this(
        namedStringSecret.getVersionCreatedAt(),
        namedStringSecret.getUuid(),
        namedStringSecret.getName(),
        namedStringSecret.getSecretType(),
        namedStringSecret.getValue()
    );
  }

  public StringView setValue(String value) {
    this.value = value;
    return this;
  }

  @Override
  public String getType() {
    return this.type;
  }

  public StringView setType(String type) {
    this.type = type;
    return this;
  }

  public String getValue() {
    return value;
  }
}
