package org.cloudfoundry.credhub.domain;

import java.io.IOException;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.JsonObjectMapper;

public class PasswordCredentialVersion extends CredentialVersion {

  private final PasswordCredentialVersionData delegate;
  private String password;
  private final JsonObjectMapper jsonObjectMapper;

  public PasswordCredentialVersion(final PasswordCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    jsonObjectMapper = new JsonObjectMapper();
  }

  public PasswordCredentialVersion(final String name) {
    this(new PasswordCredentialVersionData(name));
  }

  public PasswordCredentialVersion() {
    this(new PasswordCredentialVersionData());
  }

  public PasswordCredentialVersion(
    final StringCredentialValue password,
    final StringGenerationParameters generationParameters,
    final Encryptor encryptor
  ) {
    this();
    setEncryptor(encryptor);
    setPasswordAndGenerationParameters(password.getStringCredential(), generationParameters);
  }

  public String getPassword() {
    if (password == null) {
      password = encryptor.decrypt(delegate.getEncryptedValueData());
    }
    return password;
  }

  public void setPasswordAndGenerationParameters(
    final String password,
    final StringGenerationParameters generationParameters
  ) {
    if (password == null) {
      throw new IllegalArgumentException("password cannot be null");
    }

    try {
      final String generationParameterJson = generationParameters != null ? jsonObjectMapper.writeValueAsString(generationParameters) : null;

      if (generationParameterJson != null) {
        final EncryptedValue encryptedParameters = encryptor.encrypt(generationParameterJson);
        delegate.setEncryptedGenerationParameters(encryptedParameters);
      }

      final EncryptedValue encryptedPassword = encryptor.encrypt(password);
      delegate.setEncryptedValueData(encryptedPassword);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public StringGenerationParameters getGenerationParameters() {

    if (delegate.getEncryptedGenerationParameters() == null) {
      return null;
    }

    final String parameterJson = encryptor.decrypt(delegate.getEncryptedGenerationParameters());

    if (parameterJson == null) {
      return null;
    }

    try {
      final String password = getPassword();

      final StringGenerationParameters passwordGenerationParameters = jsonObjectMapper
        .deserializeBackwardsCompatibleValue(parameterJson, StringGenerationParameters.class);

      passwordGenerationParameters.setLength(password.length());

      return passwordGenerationParameters;
    } catch (final IOException e) {
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

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  @Override
  public void rotate() {
    final String decryptedPassword = this.getPassword();
    final StringGenerationParameters decryptedGenerationParameters = this.getGenerationParameters();
    this.setPasswordAndGenerationParameters(decryptedPassword, decryptedGenerationParameters);
  }
}
