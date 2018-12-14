package org.cloudfoundry.credhub.request;

import java.util.Arrays;
import java.util.List;

import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

public class RsaSshGenerationParameters extends GenerationParameters {
  private int keyLength = 2048;
  private final List<Integer> validKeyLengths = Arrays.asList(2048, 3072, 4096);

  @Override
  public void validate() {
    if (!validKeyLengths.contains(keyLength)) {
      throw new ParameterizedValidationException("error.invalid_key_length");
    }
  }

  public Integer getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(final int keyLength) {
    this.keyLength = keyLength;
  }
}
