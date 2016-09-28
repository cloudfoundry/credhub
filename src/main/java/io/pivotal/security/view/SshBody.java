package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SshBody {

  @JsonProperty("public_key")
  private String publicKey;
  @JsonProperty("private_key")
  private String privateKey;

  public SshBody(String publicKey, String privateKey) {
    this
        .setPublicKey(publicKey)
        .setPrivateKey(privateKey);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public SshBody setPublicKey(String publicKey) {
    this.publicKey = publicKey;
    return this;
  }

  public String getPrivateKey() { return privateKey; }

  public SshBody setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
    return this;
  }
}
