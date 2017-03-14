package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.validator.ValidTypeForGeneration;
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
    defaultImpl = DefaultSecretGenerateRequest.class  // TEMPORARY: Only needed while we're removing DocumentContext
)
@JsonSubTypes({
    @JsonSubTypes.Type(name = "password", value = PasswordGenerateRequest.class)
})
@ValidTypeForGeneration(message = "error.invalid_generate_type")
//@ValidRegenerateRequest(message = "error.invalid_regenerate_parameters")
abstract public class BaseSecretGenerateRequest {
  private String type;

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = "^(?>(?:/?[^/]+))*$", message = "error.invalid_name_has_slash")
  private String name;

  private boolean overwrite;

  private boolean regenerate;

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

  public boolean isRegenerate() {
    return regenerate;
  }

  public void setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  @JsonIgnore
  abstract public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor);

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
}
