package io.pivotal.security.controller.v1;

import org.springframework.stereotype.Component;

@Component
public class SshSecretParameters extends RsaSshSecretParameters {
  private String sshComment = "";

  public String getSshComment() {
    return sshComment;
  }

  public void setSshComment(String sshComment) {
    this.sshComment = sshComment;
  }
}
