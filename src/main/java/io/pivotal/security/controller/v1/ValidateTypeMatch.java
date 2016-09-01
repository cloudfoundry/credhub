package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.view.SecretKind;

import javax.validation.ValidationException;

class ValidateTypeMatch implements SecretKind.Mapping<NamedSecret, NamedSecret> {
  @Override
  public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedValueSecret)) throw new ValidationException("error.type_mismatch");
    return namedSecret;
  }

  @Override
  public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedPasswordSecret)) throw new ValidationException("error.type_mismatch");
    return namedSecret;
  }

  @Override
  public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
    if (namedSecret != null && !(namedSecret instanceof NamedCertificateSecret)) throw new ValidationException("error.type_mismatch");
    return namedSecret;
  }
}
