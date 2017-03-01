package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.hibernate.validator.constraints.NotEmpty;

public class PasswordSetRequest extends BaseSecretSetRequest {
  @NotEmpty
  @JsonProperty("value")
  private String password;

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}
