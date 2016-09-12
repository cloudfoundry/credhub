package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import org.springframework.stereotype.Component;

import static com.google.common.collect.ImmutableSet.of;
import static org.apache.commons.lang3.StringUtils.isEmpty;

import io.pivotal.security.view.ParameterizedValidationException;

import java.util.Set;

@Component
public class CertificateSetRequestTranslator implements RequestTranslator<NamedCertificateSecret> {

  @Override
  public void populateEntityFromJson(NamedCertificateSecret namedCertificateSecret, DocumentContext documentContext) {
    String root = emptyToNull(documentContext.read("$.value.ca"));
    String certificate = emptyToNull(documentContext.read("$.value.certificate"));
    String privateKey = emptyToNull(documentContext.read("$.value.private_key"));
    if (root == null && certificate == null && privateKey == null) {
      throw new ParameterizedValidationException("error.missing_certificate_credentials");
    }
    namedCertificateSecret.setCa(root);
    namedCertificateSecret.setCertificate(certificate);
    namedCertificateSecret.setPrivateKey(privateKey);
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['type']", "$['overwrite']", "$['value']",
        "$['value']['ca']", "$['value']['certificate']", "$['value']['private_key']");
  }

  private String emptyToNull(String val) {
    return isEmpty(val) ? null : val;
  }
}
