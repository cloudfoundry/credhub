package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.request.GenerationParameters;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.JsonObjectMapper;
import org.springframework.util.Assert;

import java.io.IOException;

public class PasswordCredentialVersion extends CredentialVersion<PasswordCredentialVersion> {

  private PasswordCredentialVersionData delegate;
  private String password;
  private JsonObjectMapper jsonObjectMapper;

  public PasswordCredentialVersion(PasswordCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    jsonObjectMapper = new JsonObjectMapper();
  }

  public PasswordCredentialVersion(String name) {
    this(new PasswordCredentialVersionData(name));
  }

  public PasswordCredentialVersion() {
    this(new PasswordCredentialVersionData());
  }

  public PasswordCredentialVersion(
      StringCredentialValue password,
      StringGenerationParameters generationParameters,
      Encryptor encryptor
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

  public PasswordCredentialVersion setPasswordAndGenerationParameters(String password,
                                                                      StringGenerationParameters generationParameters) {
    EncryptedValue encryptedParameters, encryptedPassword;
    if (password == null) {
      throw new IllegalArgumentException("password cannot be null");
    }

    try {
      String generationParameterJson =
          generationParameters != null ? jsonObjectMapper.writeValueAsString(generationParameters)
              : null;
      if (generationParameterJson != null) {
        encryptedParameters = encryptor.encrypt(generationParameterJson);
        delegate.setEncryptedGenerationParameters(encryptedParameters);
      }

      encryptedPassword = encryptor.encrypt(password);
      delegate.setEncryptedValueData(encryptedPassword);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return this;
  }

  public StringGenerationParameters getGenerationParameters() {
    String password = getPassword();
    Assert.notNull(password,
        "Password length generation parameter cannot be restored without an existing password");

    if (delegate.getEncryptedGenerationParameters() == null) {
      return null;
    }

    String parameterJson = encryptor.decrypt(delegate.getEncryptedGenerationParameters());

    if (parameterJson == null) {
      return null;
    }

    try {
      StringGenerationParameters passwordGenerationParameters = jsonObjectMapper
          .deserializeBackwardsCompatibleValue(parameterJson, StringGenerationParameters.class);
      passwordGenerationParameters.setLength(password.length());
      return passwordGenerationParameters;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean matchesGenerationParameters(GenerationParameters generationParameters) {
    return generationParameters.equals(getGenerationParameters());
  }

  @Override
  public String getCredentialType() {
    return delegate.getCredentialType();
  }

  public void rotate() {
    String decryptedPassword = this.getPassword();
    StringGenerationParameters decryptedGenerationParameters = this.getGenerationParameters();
    this.setPasswordAndGenerationParameters(decryptedPassword, decryptedGenerationParameters);
  }
}
