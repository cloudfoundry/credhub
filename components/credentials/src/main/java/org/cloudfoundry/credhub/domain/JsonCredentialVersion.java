package org.cloudfoundry.credhub.domain;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;
import org.cloudfoundry.credhub.entity.JsonCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;

public class JsonCredentialVersion extends CredentialVersion {

  private final JsonObjectMapper objectMapper;
  private final JsonCredentialVersionData delegate;

  public JsonCredentialVersion() {
    this(new JsonCredentialVersionData());
  }

  public JsonCredentialVersion(final JsonCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    /*
    It is alright to use a "new" ObjectMapper here because the JSON data does
    not have properties that is maps to, thereby not facing a problem with the
    casing being defined. Using JsonObjectMapper for consistency across project.
     */
    this.objectMapper = new JsonObjectMapper();
  }

  public JsonCredentialVersion(final String name) {
    this(new JsonCredentialVersionData(name));
  }

  public JsonCredentialVersion(final JsonCredentialValue jsonValue, final Encryptor encryptor) {
    this();
    this.setEncryptor(encryptor);
    this.setValue(jsonValue.getValue());
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    final JsonNode value = this.getValue();
    this.setValue(value);
  }

  @Override
  public JsonNode getValue() {
    final String serializedValue = (String) super.getValue();
    try {
      return objectMapper.readTree(serializedValue);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  public void setValue(final JsonNode value) {
    if (value == null) {
      throw new ParameterizedValidationException("error.missing_value");
    }

    try {
      final String serializedString = objectMapper.writeValueAsString(value);

      super.setValue(serializedString);
    } catch (final JsonProcessingException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean matchesGenerationParameters(final GenerationParameters generationParameters) {
    return generationParameters == null;
  }

  @Override
  public GenerationParameters getGenerationParameters() {
    return null;
  }
}
