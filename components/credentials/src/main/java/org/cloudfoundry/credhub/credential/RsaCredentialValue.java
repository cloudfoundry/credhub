package org.cloudfoundry.credhub.credential;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.utils.EmptyStringToNull;
import org.cloudfoundry.credhub.validators.RequireAnyOf;

@RequireAnyOf(
  message = ErrorMessages.MISSING_RSA_SSH_PARAMETERS,
  fields = {
    "publicKey",
    "privateKey",
  }
)
@JsonAutoDetect
public class RsaCredentialValue implements CredentialValue {

  @JsonDeserialize(using = EmptyStringToNull.class)
  private String publicKey;
  @JsonDeserialize(using = EmptyStringToNull.class)
  private String privateKey;

  @SuppressWarnings("unused")
  public RsaCredentialValue() {
    super();
  }

  public RsaCredentialValue(final String publicKey, final String privateKey) {
    super();
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    RsaCredentialValue that = (RsaCredentialValue) o;
    return Objects.equals(publicKey, that.publicKey) &&
      Objects.equals(privateKey, that.privateKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(publicKey, privateKey);
  }
}
