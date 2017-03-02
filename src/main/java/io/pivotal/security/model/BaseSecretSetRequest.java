package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import org.hibernate.validator.constraints.NotEmpty;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = "type",
    visible = true,
    defaultImpl = DefaultSecretSetRequest.class
)
@JsonSubTypes({
    @JsonSubTypes.Type(name = "password",value = PasswordSetRequest.class),
})
public class BaseSecretSetRequest {

  @NotEmpty
  private String name;

  @NotEmpty
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
  public NamedSecret createNewVersion(NamedSecret existing, String name, Encryptor encryptor) {
    throw new RuntimeException("unimplemented");
  }

}
