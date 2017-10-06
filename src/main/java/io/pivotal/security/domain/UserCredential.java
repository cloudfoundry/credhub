package io.pivotal.security.domain;

import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.entity.UserCredentialVersionData;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.JsonObjectMapper;

import java.io.IOException;

public class UserCredential extends Credential<UserCredential> {
  private final UserCredentialVersionData delegate;
  private StringGenerationParameters generationParameters;
  private JsonObjectMapper jsonObjectMapper;

  public UserCredential() {
    this(new UserCredentialVersionData());
  }

  public UserCredential(UserCredentialVersionData delegate) {
    super(delegate);
    this.delegate = delegate;
    jsonObjectMapper = new JsonObjectMapper();
  }

  public UserCredential(String name) {
    this(new UserCredentialVersionData(name));
  }

  public UserCredential(
      UserCredentialValue userValue,
      StringGenerationParameters generationParameters,
      Encryptor encryptor
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
    String decryptedPassword = getPassword();
    StringGenerationParameters decryptedGenerationParameters = getGenerationParameters();

    setPassword(decryptedPassword);
    setGenerationParameters(decryptedGenerationParameters);
  }

  public UserCredential setPassword(String password) {
    if (password != null) {
      super.setValue(password);
    }
    return this;
  }

  public String getPassword() {
    return (String) super.getValue();
  }

  public UserCredential setUsername(String username) {
    delegate.setUsername(username);
    return this;
  }

  public String getUsername() {
    return delegate.getUsername();
  }

  public String getSalt() {
    return delegate.getSalt();
  }

  public UserCredential setSalt(String salt) {
    delegate.setSalt(salt);
    return this;
  }

  public UserCredential setGenerationParameters(StringGenerationParameters generationParameters) {
    Encryption encryptedParameters;
    try {
      String generationParameterJson =
          generationParameters != null ? jsonObjectMapper.writeValueAsString(generationParameters)
              : null;
      if (generationParameterJson != null) {
        encryptedParameters = encryptor.encrypt(generationParameterJson);
        delegate.setEncryptedGenerationParameters(encryptedParameters);
      }

    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    return this;
  }

  public StringGenerationParameters getGenerationParameters() {
    String parameterJson = encryptor.decrypt(new Encryption(
        delegate.getEncryptedGenerationParameters().getEncryptionKeyUuid(),
        delegate.getEncryptedGenerationParameters().getEncryptedValue(),
        delegate.getEncryptedGenerationParameters().getNonce())
    );

    if (parameterJson == null) {
      return null;
    }

    try {
      StringGenerationParameters generationParameters = jsonObjectMapper
          .deserializeBackwardsCompatibleValue(parameterJson, StringGenerationParameters.class);
      return generationParameters;
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
