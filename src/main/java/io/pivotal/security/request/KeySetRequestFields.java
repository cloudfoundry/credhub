package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import io.pivotal.security.validator.RequireAnyOf;

@SuppressWarnings("unused")
@RequireAnyOf(message = "error.missing_rsa_ssh_parameters", fields = { "publicKey", "privateKey" })
@JsonAutoDetect
public class KeySetRequestFields {
  private String privateKey;
  private String publicKey;

  public KeySetRequestFields() {}

  public KeySetRequestFields(String privateKey, String publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public void setPublicKey(String publicKey) {
    this.publicKey = publicKey;
  }
}
