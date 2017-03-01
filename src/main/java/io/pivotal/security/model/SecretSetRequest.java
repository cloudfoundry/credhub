package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.NotNull;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

@JsonTypeInfo(
    use = JsonTypeInfo.Id.NAME,
    include = JsonTypeInfo.As.PROPERTY,
    property = "type",
    visible = true,
    defaultImpl = PasswordSetRequest.class
)
@JsonSubTypes({
    @JsonSubTypes.Type(value = PasswordSetRequest.class, name = "password"),
})
public class SecretSetRequest {
  @NotEmpty
  private String name;
  @NotEmpty
  private String type;
  @NotNull
  private Object value;
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

  public Object getValue() {
    return value;
  }

  public void setValue(Object value) {
    this.value = value;
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
}
