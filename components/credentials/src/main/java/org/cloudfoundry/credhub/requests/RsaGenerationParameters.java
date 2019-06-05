package org.cloudfoundry.credhub.requests;

import java.util.Objects;

public class RsaGenerationParameters extends RsaSshGenerationParameters {
  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final RsaGenerationParameters that = (RsaGenerationParameters) o;
    return Objects.equals(getKeyLength(), that.getKeyLength());
  }
}
