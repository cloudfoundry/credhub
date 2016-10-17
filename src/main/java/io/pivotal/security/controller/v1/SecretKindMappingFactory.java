package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.view.SecretKind;

import java.security.NoSuchAlgorithmException;
import java.util.function.Function;

public interface SecretKindMappingFactory {
  SecretKind.CheckedMapping<NamedSecret, NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsed);

  default <Z extends NamedSecret> Z processSecret(Z existingNamedSecret, Function<String, Z> constructor, String secretPath, RequestTranslator<Z> requestTranslator, DocumentContext parsed) throws NoSuchAlgorithmException {
    Z result = existingNamedSecret == null ? constructor.apply(secretPath) : existingNamedSecret;
    requestTranslator.validatePathName(secretPath);
    requestTranslator.validateJsonKeys(parsed);
    requestTranslator.populateEntityFromJson(result, parsed);
    return result;
  }
}
