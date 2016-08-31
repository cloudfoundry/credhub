package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.view.SecretKind;

public interface SecretKindMappingFactory {
  SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed);
}
