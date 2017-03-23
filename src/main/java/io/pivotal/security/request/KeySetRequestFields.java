package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.pivotal.security.validator.RequireAnyOf;
import io.pivotal.security.util.EmptyStringToNull;

@SuppressWarnings("unused")
@RequireAnyOf(message = "error.missing_rsa_ssh_parameters", fields = { "publicKey", "privateKey" })
@JsonAutoDetect
public class KeySetRequestFields {
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
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
