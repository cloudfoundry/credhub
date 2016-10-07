package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedRsaSecret;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.google.common.collect.ImmutableSortedSet.of;
import static io.pivotal.security.util.StringUtil.emptyToNull;

@Component
public class RsaSetRequestTranslator implements RequestTranslator<NamedRsaSecret> {

  @Override
  public void populateEntityFromJson(NamedRsaSecret namedRsaSecret, DocumentContext documentContext) {
    String publicKey = emptyToNull(documentContext.read("$.value.public_key"));
    String privateKey = emptyToNull(documentContext.read("$.value.private_key"));

    namedRsaSecret.setPublicKey(publicKey);
    namedRsaSecret.setPrivateKey(privateKey);
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['type']", "$['overwrite']", "$['value']",
        "$['value']['public_key']", "$['value']['private_key']");
  }
}
