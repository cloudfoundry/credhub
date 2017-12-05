package org.cloudfoundry.credhub.credential;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.credhub.util.EmptyStringToNull;
import org.cloudfoundry.credhub.validator.RequireAnyOf;

import static com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY;

@RequireAnyOf(message = "error.missing_rsa_ssh_parameters", fields = {"publicKey", "privateKey"})
@JsonAutoDetect
public class SshCredentialValue implements CredentialValue {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String publicKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;
  private String publicKeyFingerprint;

  @SuppressWarnings("unused")
  public SshCredentialValue() {}

  public SshCredentialValue(String publicKey, String privateKey, String publicKeyFingerprint) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.publicKeyFingerprint = publicKeyFingerprint;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  @JsonProperty(access = READ_ONLY)
  @SuppressWarnings("unused")
  public String getPublicKeyFingerprint() {
    return publicKeyFingerprint;
  }
}
