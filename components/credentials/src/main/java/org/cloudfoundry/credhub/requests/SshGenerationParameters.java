package org.cloudfoundry.credhub.requests;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonInclude;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

@JsonInclude(NON_DEFAULT)
public class SshGenerationParameters extends RsaSshGenerationParameters {

  private String sshComment = "";

  public String getSshComment() {
    return sshComment;
  }

  public void setSshComment(final String sshComment) {
    this.sshComment = sshComment;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final SshGenerationParameters that = (SshGenerationParameters) o;
    return
      Objects.equals(sshComment, that.sshComment) &&
        Objects.equals(getKeyLength(), that.getKeyLength());
  }

  @Override
  public int hashCode() {
    return Objects.hash(sshComment, getKeyLength());
  }
}
