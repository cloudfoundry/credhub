package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonInclude;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

@JsonInclude(NON_DEFAULT)
public class SshGenerationParameters extends RsaSshGenerationParameters {

  private String sshComment = "";

  public String getSshComment() {
    return sshComment;
  }

  public void setSshComment(String sshComment) {
    this.sshComment = sshComment;
  }
}
