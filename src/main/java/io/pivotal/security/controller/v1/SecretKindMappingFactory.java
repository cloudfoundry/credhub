package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.view.SecretKind;

import java.util.function.Function;

public interface SecretKindMappingFactory {
  SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed);

  default <Z extends NamedSecret> Z processSecret(Z namedSecret, Function<String, Z> constructor, String secretPath, RequestTranslator<Z> requestTranslator, DocumentContext parsed) {
    Z result = namedSecret == null ? constructor.apply(secretPath) : namedSecret;
    requestTranslator.validateJsonKeys(parsed);
    requestTranslator.populateEntityFromJson(result, parsed);
    return result;
  }

}
