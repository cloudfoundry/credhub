package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.*;
import io.pivotal.security.view.SecretKind;

import io.pivotal.security.view.ParameterizedValidationException;

class ValidateTypeMatch implements SecretKind.Mapping<NamedSecret, NamedSecret> {
  @Override
  public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedValueSecret)) throw new ParameterizedValidationException("error.type_mismatch");
    return namedSecret;
  }

  @Override
  public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedPasswordSecret)) throw new ParameterizedValidationException("error.type_mismatch");
    return namedSecret;
  }

  @Override
  public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedCertificateSecret)) throw new ParameterizedValidationException("error.type_mismatch");
    return namedSecret;
  }

  @Override
  public NamedSecret ssh(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedSshSecret)) throw new ParameterizedValidationException("error.type_mismatch");
    return namedSecret;
  }
}
