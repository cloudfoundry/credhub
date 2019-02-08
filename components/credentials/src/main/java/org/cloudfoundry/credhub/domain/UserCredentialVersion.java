package org.cloudfoundry.credhub.domain;

import java.io.IOException;

import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.requests.GenerationParameters;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;

public class UserCredentialVersion extends CredentialVersion {
  private final UserCredentialVersionData delegate;
  private final JsonObjectMapper jsonObjectMapper;
  private String password;

  public UserCredentialVersion() {
    this(new UserCredentialVersionData());
  }

  public UserCredentialVersion(final UserCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    jsonObjectMapper = new JsonObjectMapper();
  }

  public UserCredentialVersion(final String name) {
    this(new UserCredentialVersionData(name));
  }

  public UserCredentialVersion(
    final UserCredentialValue userValue,
    final StringGenerationParameters generationParameters,
    final Encryptor encryptor
  ) {
    this();
    this.setEncryptor(encryptor);
    this.setPassword(userValue.getPassword());
    this.setUsername(userValue.getUsername());
    this.setGenerationParameters(generationParameters);
    this.setSalt(userValue.getSalt());
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    final String decryptedPassword = getPassword();
    final StringGenerationParameters decryptedGenerationParameters = getGenerationParameters();

    setPassword(decryptedPassword);
    setGenerationParameters(decryptedGenerationParameters);
  }

  public String getPassword() {
    this.password = (String) super.getValue();
    return this.password;
  }

  public void setPassword(final String password) {
    if (password != null) {
      super.setValue(password);
    }
  }

  public String getUsername() {
    return delegate.getUsername();
  }

  public void setUsername(final String username) {
    delegate.setUsername(username);
  }

  public String getSalt() {
    return delegate.getSalt();
  }

  public void setSalt(final String salt) {
    delegate.setSalt(salt);
  }

  @Override
  public StringGenerationParameters getGenerationParameters() {
    final String parameterJson = encryptor.decrypt(delegate.getEncryptedGenerationParameters());

    if (parameterJson == null) {
      return null;
    }

    try {
      final StringGenerationParameters generationParameters = jsonObjectMapper
        .deserializeBackwardsCompatibleValue(parameterJson, StringGenerationParameters.class);

      final String password = this.password == null ? getPassword() : this.password;

      generationParameters.setLength(password.length());

      return generationParameters;
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  public void setGenerationParameters(final StringGenerationParameters generationParameters) {
    final EncryptedValue encryptedParameters;
    try {
      final String generationParameterJson =
        generationParameters != null ? jsonObjectMapper.writeValueAsString(generationParameters)
          : null;
      if (generationParameterJson != null) {
        encryptedParameters = encryptor.encrypt(generationParameterJson);
        delegate.setEncryptedGenerationParameters(encryptedParameters);
      }

    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean matchesGenerationParameters(final GenerationParameters generationParameters) {
    if (generationParameters == null) {
      return true;
    }

    return generationParameters.equals(getGenerationParameters());
  }
}
