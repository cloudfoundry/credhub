package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.view.CertificateAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;

@Component
public class CertificateAuthorityRequestTranslator implements AuthoritySetterRequestTranslator {

  @Override
  public CertificateAuthority createAuthorityFromJson(DocumentContext parsed) throws ValidationException {
    String type = parsed.read("$.type");
    if (!"root".equals(type)) {
      throw new ValidationException("error.type_invalid");
    }
    String certificate = parsed.read("$.root.certificate");
    String privateKey = parsed.read("$.root.private");
    certificate = StringUtils.isEmpty(certificate) ? null : certificate;
    privateKey = StringUtils.isEmpty(privateKey) ? null : privateKey;
    if (certificate == null || privateKey == null) {
      throw new ValidationException("error.missing_ca_credentials");
    }
    return new CertificateAuthority(type, certificate, privateKey);
  }

  @Override
  public NamedCertificateAuthority makeEntity(String name) {
    return new NamedCertificateAuthority(name);
  }
}