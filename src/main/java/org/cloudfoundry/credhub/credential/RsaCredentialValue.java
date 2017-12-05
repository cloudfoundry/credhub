package org.cloudfoundry.credhub.credential;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.credhub.util.EmptyStringToNull;
import org.cloudfoundry.credhub.validator.RequireAnyOf;

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
