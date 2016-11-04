package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedRsaSshSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.stereotype.Component;

import static com.google.common.collect.ImmutableSortedSet.of;
import static io.pivotal.security.util.StringUtil.emptyToNull;

import java.util.Set;

@Component
public class RsaSshSetRequestTranslator implements RequestTranslator<NamedRsaSshSecret> {

  @Override
  public void populateEntityFromJson(NamedRsaSshSecret namedRsaSshSecret, DocumentContext documentContext) {
    String publicKey = emptyToNull(documentContext.read("$.value.public_key"));
    String privateKey = emptyToNull(documentContext.read("$.value.private_key"));

    if (publicKey == null && privateKey == null) {
      throw new ParameterizedValidationException("error.missing_rsa_ssh_parameters");
    }

    namedRsaSshSecret.setPublicKey(publicKey);
    namedRsaSshSecret.setPrivateKey(privateKey);
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['type']", "$['name']", "$['overwrite']", "$['value']",
        "$['value']['public_key']", "$['value']['private_key']");
  }
}
