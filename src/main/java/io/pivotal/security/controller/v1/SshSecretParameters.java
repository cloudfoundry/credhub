package io.pivotal.security.controller.v1;

import org.springframework.stereotype.Component;

@Component
public class SshSecretParameters implements RequestParameters {
  private Integer keyLength = 2048;

  @Override
  public String getType() {
    throw new UnsupportedOperationException();
  }

  public void setKeyLength(Integer keyLength) {
    this.keyLength = keyLength;
  }

  public void validate() {

  }

  public Integer getKeyLength() {
    return keyLength;
  }
}
