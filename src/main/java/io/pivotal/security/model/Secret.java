package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

public class Secret {

  @NotNull
  public String value;

  @NotNull
  @Pattern(regexp = "value")
  public String type;

  @JsonCreator
  public static Secret make(@JsonProperty("type") String type, @JsonProperty("value") String value) {
    if (value == null) throw new java.lang.IllegalArgumentException("Parameter specified as non-null is null: method io.pivotal.security.model.Secret.make, parameter value");
    Secret secret = new Secret();
    secret.value = value;
    secret.type = type;
    return secret;
  }
}