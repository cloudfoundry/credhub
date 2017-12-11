package org.cloudfoundry.credhub.constants;

import com.fasterxml.jackson.annotation.JsonValue;

public enum CredentialWriteMode {
  OVERWRITE("overwrite"),
  NO_OVERWRITE("no-overwrite"),
  CONVERGE("converge");

  public final String mode;

  @JsonValue
  public String forJackson() {
    return mode;
  }

  CredentialWriteMode(String mode) {
    this.mode = mode;
  }
}
