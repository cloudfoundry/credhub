package io.pivotal.security.domain;

import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.view.SecretKind;

public class NamedPasswordSecret extends NamedStringSecret<NamedPasswordSecret> {

  private NamedPasswordSecretData delegate;

  public NamedPasswordSecret(NamedPasswordSecretData delegate) {
    super(delegate);
    this.delegate = delegate;
  }

  public NamedPasswordSecret(String name) {
    this(new NamedPasswordSecretData(name));
  }

  public NamedPasswordSecret() {
    this(new NamedPasswordSecretData());
  }

  public byte[] getEncryptedGenerationParameters() {
    return delegate.getEncryptedGenerationParameters();
  }

  public NamedPasswordSecret setEncryptedGenerationParameters(byte[] encryptedGenerationParameters) {
    delegate.setEncryptedGenerationParameters(encryptedGenerationParameters);
    return this;
  }

  public byte[] getParametersNonce() {
    return delegate.getParametersNonce();
  }

  public NamedPasswordSecret setParametersNonce(byte[] parametersNonce) {
    delegate.setParametersNonce(parametersNonce);
    return this;
  }

  public PasswordGenerationParameters getGenerationParameters() {
    return delegate.getGenerationParameters();
  }

  public NamedPasswordSecret setGenerationParameters(PasswordGenerationParameters generationParameters) {
    delegate.setGenerationParameters(generationParameters);
    return this;
  }

  @Override
  public String getSecretType() {
    return delegate.getSecretType();
  }

  @Override
  void copyIntoImpl(NamedPasswordSecret copy) {
    delegate.copyIntoImpl(copy.delegate);
  }

  @Override
  public SecretKind getKind() {
    return delegate.getKind();
  }
}
