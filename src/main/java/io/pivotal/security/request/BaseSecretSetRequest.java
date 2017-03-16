package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.Pattern;
import java.util.ArrayList;
import java.util.List;

@JsonTypeInfo(
    use         = JsonTypeInfo.Id.NAME,
    include     = JsonTypeInfo.As.PROPERTY,
    property    = "type",
    visible     = true
)
@JsonSubTypes({
    @JsonSubTypes.Type(name = "password",     value = PasswordSetRequest.class),
    @JsonSubTypes.Type(name = "value",        value = ValueSetRequest.class),
    @JsonSubTypes.Type(name = "certificate",  value = CertificateSetRequest.class),
    @JsonSubTypes.Type(name = "json",         value = JsonSetRequest.class),
    @JsonSubTypes.Type(name = "ssh",          value = SshSetRequest.class),
    @JsonSubTypes.Type(name = "rsa",          value = RsaSetRequest.class)
})
abstract public class BaseSecretSetRequest {
  public static final String STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES = "^(?>(?:/?[^/]+))*$";

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES, message = "error.invalid_name_has_slash")
  private String name;

  @NotEmpty(message = "error.type_invalid")
  private String type;

  private boolean overwrite;

  private List<AccessControlEntry> accessControlEntries = new ArrayList<>();

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public boolean isOverwrite() {
    return overwrite;
  }

  public void setOverwrite(boolean overwrite) {
    this.overwrite = overwrite;
  }

  public List<AccessControlEntry> getAccessControlEntries() {
    return accessControlEntries;
  }

  public void setAccessControlEntries(List<AccessControlEntry> accessControlEntries) {
    this.accessControlEntries = accessControlEntries;
  }

  @JsonIgnore
  abstract public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor);
}
