package io.pivotal.security.view;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedRsaSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.entity.NamedValueSecret;

public interface SecretKindFromString {

  static SecretKind fromString(String type) {
    if (type == null) {
      throw new ParameterizedValidationException("error.type_invalid");
    }
    switch (type) {
      case NamedValueSecret.SECRET_TYPE:
        return SecretKind.VALUE;
      case NamedPasswordSecret.SECRET_TYPE:
        return SecretKind.PASSWORD;
      case NamedCertificateSecret.SECRET_TYPE:
        return SecretKind.CERTIFICATE;
      case NamedSshSecret.SECRET_TYPE:
        return SecretKind.SSH;
      case NamedRsaSecret.SECRET_TYPE:
        return SecretKind.RSA;
    }
    throw new ParameterizedValidationException("error.type_invalid");
  }
}
