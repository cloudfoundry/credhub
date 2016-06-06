package io.pivotal.security.model;

import javax.validation.constraints.NotNull;

public class StringSecret {

  @NotNull
  public String value;

  public final String type = "value";

  public static StringSecret make(String value) {
    if (value == null) {
      throw new java.lang.IllegalArgumentException("Parameter specified as non-null is null: method io.pivotal.security.model.Secret.make, parameter value");
    }
    StringSecret stringSecret = new StringSecret();
    stringSecret.value = value;
    return stringSecret;
  }
}