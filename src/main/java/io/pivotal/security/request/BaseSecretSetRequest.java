package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.Pattern;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@JsonTypeInfo(
    use         = JsonTypeInfo.Id.NAME,
    include     = JsonTypeInfo.As.PROPERTY,
    property    = "type",
    visible     = true,
    defaultImpl = DefaultSecretSetRequest.class
)
@JsonSubTypes({
    @JsonSubTypes.Type(name = "password",     value = PasswordSetRequest.class),
    @JsonSubTypes.Type(name = "value",        value = ValueSetRequest.class),
    @JsonSubTypes.Type(name = "certificate",  value = CertificateSetRequest.class),
    @JsonSubTypes.Type(name = "json",         value = JsonSetRequest.class),
    @JsonSubTypes.Type(name = "ssh",          value = SshSecretSetRequest.class)
})
abstract public class BaseSecretSetRequest {
  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = "^(?>(?:/?[^/]+))*$", message = "error.invalid_name_has_slash")
  private String name;

  @NotEmpty(message = "error.type_invalid")
  private String type;

  private boolean overwrite;

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

  // TEMPORARY: Only needed while we're removing DocumentContext
  @JsonIgnore
  public InputStream getInputStream() {
    try {
      final ObjectMapper objectMapper = new ObjectMapper()
          .setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);
      return new ByteArrayInputStream(objectMapper.writeValueAsBytes(this));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @JsonIgnore
  abstract public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor);
}
