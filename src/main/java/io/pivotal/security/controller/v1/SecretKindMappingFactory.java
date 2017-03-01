package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.view.SecretKind;

import java.security.NoSuchAlgorithmException;
import java.util.function.Function;

public interface SecretKindMappingFactory {
  SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest);

  default <Z extends NamedSecret> Z createNewSecret(
      Z existingNamedSecret,
      Function<String, Z> secretConstructor,
      String secretPath,
      RequestTranslator<Z> requestTranslator,
      DocumentContext parsedRequest,
      Encryptor encryptor
  ) throws NoSuchAlgorithmException {
    Z result = secretConstructor.apply(secretPath);
    result.setEncryptor(encryptor);

    if (existingNamedSecret != null) {
      existingNamedSecret.copyInto(result);
    }

    RequestTranslator.validatePathName(secretPath);
    requestTranslator.validateJsonKeys(parsedRequest);
    requestTranslator.populateEntityFromJson(result, parsedRequest);

    return result;
  }
}
