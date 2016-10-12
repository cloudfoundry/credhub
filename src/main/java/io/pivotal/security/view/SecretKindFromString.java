package io.pivotal.security.view;

public interface SecretKindFromString {

  static SecretKind fromString(String type) {
    switch (type) {
      case "value":
        return SecretKind.VALUE;
      case "password":
        return SecretKind.PASSWORD;
      case "certificate":
        return SecretKind.CERTIFICATE;
      case "ssh":
        return SecretKind.SSH;
      case "rsa":
        return SecretKind.RSA;
    }
    throw new ParameterizedValidationException("error.type_invalid");
  }
}
