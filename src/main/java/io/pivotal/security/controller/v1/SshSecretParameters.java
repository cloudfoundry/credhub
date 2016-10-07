package io.pivotal.security.controller.v1;

import org.springframework.stereotype.Component;

@Component
public class SshSecretParameters implements RequestParameters {
  private int keyLength = 2048;

  @Override
  public String getType() {
    throw new UnsupportedOperationException();
  }

  public void validate() {

  }

  public Integer getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }
}
