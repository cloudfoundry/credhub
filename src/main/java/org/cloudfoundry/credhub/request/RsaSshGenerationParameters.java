package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

import java.util.Arrays;
import java.util.List;

public class RsaSshGenerationParameters implements GenerationParameters{
  private int keyLength = 2048;
  private List<Integer> validKeyLengths = Arrays.asList(2048, 3072, 4096);

  public void validate() {
    if (!validKeyLengths.contains(keyLength)) {
      throw new ParameterizedValidationException("error.invalid_key_length");
    }
  }

  public Integer getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }
}
