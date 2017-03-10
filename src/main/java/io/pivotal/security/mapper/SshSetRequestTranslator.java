package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.springframework.stereotype.Component;

import java.util.Set;

import static com.google.common.collect.ImmutableSortedSet.of;
import static io.pivotal.security.util.StringUtil.emptyToNull;

@Component
public class SshSetRequestTranslator implements RequestTranslator<NamedSshSecret> {
  @Override
  public void populateEntityFromJson(NamedSshSecret namedRsaSshSecret, DocumentContext documentContext) {
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
