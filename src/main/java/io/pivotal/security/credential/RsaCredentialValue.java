package io.pivotal.security.credential;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.pivotal.security.util.EmptyStringToNull;
import io.pivotal.security.validator.RequireAnyOf;

@RequireAnyOf(message = "error.missing_rsa_ssh_parameters", fields = {"publicKey", "privateKey"})
@JsonAutoDetect
public class RsaCredentialValue implements CredentialValue {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String publicKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;

  @SuppressWarnings("unused")
  public RsaCredentialValue() {}

  public RsaCredentialValue(String publicKey, String privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }
}
