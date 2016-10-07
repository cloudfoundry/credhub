package io.pivotal.security.controller.v1;

import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;

@Component
public class SshSecretParameters implements RequestParameters {
  private int keyLength = 2048;
  private List<Integer> validKeyLengths = Arrays.asList(2048, 3072, 4096);
  private String sshComment = "";

  @Override
  public String getType() {
    throw new UnsupportedOperationException();
  }

  public void validate() {
    if (!validKeyLengths.contains(keyLength)) {
      throw new ParameterizedValidationException("error.invalid_key_length");
    }
  }

  public Integer getKeyLength() {
    return keyLength;
  }

  public String getSshComment() {
    return sshComment;
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }

  public void setSshComment(String sshComment) {
    this.sshComment = sshComment;
  }
}
