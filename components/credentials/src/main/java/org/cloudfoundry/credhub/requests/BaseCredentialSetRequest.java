package org.cloudfoundry.credhub.requests;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonTypeIdResolver;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.CredentialValue;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

@JsonTypeInfo(
  use = JsonTypeInfo.Id.CUSTOM,
  property = "type",
  visible = true
)
@JsonTypeIdResolver(SetRequestTypeIdResolver.class)
@JsonSubTypes({
  @JsonSubTypes.Type(name = "password", value = PasswordSetRequest.class),
  @JsonSubTypes.Type(name = "value", value = ValueSetRequest.class),
  @JsonSubTypes.Type(name = "certificate", value = CertificateSetRequest.class),
  @JsonSubTypes.Type(name = "json", value = JsonSetRequest.class),
  @JsonSubTypes.Type(name = "ssh", value = SshSetRequest.class),
  @JsonSubTypes.Type(name = "rsa", value = RsaSetRequest.class),
  @JsonSubTypes.Type(name = "user", value = UserSetRequest.class),
})
public abstract class BaseCredentialSetRequest<T extends CredentialValue> extends BaseCredentialRequest {

  @JsonIgnore
  public abstract T getCredentialValue();

  @Override
  public void validate() {
    super.validate();

    if (isInvalidTypeForSet(getType())) {
      throw new ParameterizedValidationException(ErrorMessages.INVALID_TYPE_WITH_SET_PROMPT);
    }

    if (getName() != null && getName().length() > 1024) {
      throw new ParameterizedValidationException(ErrorMessages.NAME_HAS_TOO_MANY_CHARACTERS);
    }

    if (getName() != null && getName().length() > 1024) {
      throw new ParameterizedValidationException(ErrorMessages.NAME_HAS_TOO_MANY_CHARACTERS);
    }
  }

  private boolean isInvalidTypeForSet(final String type) {
    return !Arrays.asList(CredentialType.values()).contains(CredentialType.valueOf(type.toUpperCase()));
  }
}
