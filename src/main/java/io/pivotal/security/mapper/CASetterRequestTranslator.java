package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class CASetterRequestTranslator implements RequestTranslator<NamedCertificateAuthority> {

  @Override
  public NamedCertificateAuthority makeEntity(String name) {
    return new NamedCertificateAuthority(name);
  }

  @Override
  public void populateEntityFromJson(NamedCertificateAuthority namedCA, DocumentContext documentContext) {
    String type = documentContext.read("$.type");
    if (!"root".equals(type)) {
      throw new ValidationException("error.type_invalid");
    }
    String certificate = documentContext.read("$.value.certificate");
    String privateKey = documentContext.read("$.value.private_key");
    certificate = StringUtils.isEmpty(certificate) ? null : certificate;
    privateKey = StringUtils.isEmpty(privateKey) ? null : privateKey;
    if (certificate == null || privateKey == null) {
      throw new ValidationException("error.missing_ca_credentials");
    }
    namedCA
        .setType(type)
        .setCertificate(certificate)
        .setPrivateKey(privateKey);
  }
}