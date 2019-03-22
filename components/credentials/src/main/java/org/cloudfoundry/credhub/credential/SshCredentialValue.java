package org.cloudfoundry.credhub.credential;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.utils.EmptyStringToNull;
import org.cloudfoundry.credhub.validators.RequireAnyOf;

import static com.fasterxml.jackson.annotation.JsonProperty.Access.READ_ONLY;

@RequireAnyOf(
  message = ErrorMessages.MISSING_RSA_SSH_PARAMETERS,
  fields = {
    "publicKey",
    "privateKey",
  }
)
@JsonAutoDetect
public class SshCredentialValue implements CredentialValue {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String publicKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;
  private String publicKeyFingerprint;

  @SuppressWarnings("unused")
  public SshCredentialValue() {
    super();
  }

  public SshCredentialValue(final String publicKey, final String privateKey, final String publicKeyFingerprint) {
    super();
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

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    SshCredentialValue that = (SshCredentialValue) o;
    return Objects.equals(publicKey, that.publicKey) &&
      Objects.equals(privateKey, that.privateKey) &&
      Objects.equals(publicKeyFingerprint, that.publicKeyFingerprint);
  }

  @Override
  public int hashCode() {
    return Objects.hash(publicKey, privateKey, publicKeyFingerprint);
  }
}
