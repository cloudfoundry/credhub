package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.view.SecretKind;

public interface SecretKindMappingFactory {
  SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed);

  default <Z extends NamedSecret> Z processSecret(Z namedSecret, Z newObj, RequestTranslator<Z> requestTranslator, DocumentContext parsed) {
    Z result = namedSecret == null ? newObj : namedSecret;
    requestTranslator.populateEntityFromJson(result, parsed);
    return result;
  }

}
