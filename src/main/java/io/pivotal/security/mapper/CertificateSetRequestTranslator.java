package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import org.springframework.stereotype.Component;

import static org.apache.commons.lang3.StringUtils.isEmpty;

import javax.validation.ValidationException;

@Component
public class CertificateSetRequestTranslator implements RequestTranslator<NamedCertificateSecret> {

  @Override
  public NamedCertificateSecret makeEntity(String name) {
    return new NamedCertificateSecret(name);
  }

  @Override
  public NamedCertificateSecret populateEntityFromJson(NamedCertificateSecret namedCertificateSecret, DocumentContext documentContext) {
    String root = emptyToNull(documentContext.read("$.value.root"));
    String certificate = emptyToNull(documentContext.read("$.value.certificate"));
    String privateKey = emptyToNull(documentContext.read("$.value.private_key"));
    if (root == null && certificate == null && privateKey == null) {
      throw new ValidationException("error.missing_certificate_credentials");
    }
    namedCertificateSecret.setRoot(root);
    namedCertificateSecret.setCertificate(certificate);
    namedCertificateSecret.setPrivateKey(privateKey);
    return  namedCertificateSecret;
  }

  private String emptyToNull(String val) {
    return isEmpty(val) ? null : val;
  }
}
