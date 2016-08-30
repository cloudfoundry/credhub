package io.pivotal.security.view;

import javax.validation.ValidationException;

public interface SecretKindFromString {

  static SecretKind fromString(String type) throws ValidationException {
    if (type == null) {
      throw new ValidationException("error.type_invalid");
    }
    switch (type) {
      case "value":
        return SecretKind.VALUE;
      case "password":
        return SecretKind.PASSWORD;
      case "certificate":
        return SecretKind.CERTIFICATE;
    }
    throw new ValidationException("error.type_invalid");
  }
}
