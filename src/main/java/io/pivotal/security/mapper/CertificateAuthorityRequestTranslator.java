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
    String pub = parsed.read("$.root.public");
    String priv = parsed.read("$.root.private");
    pub = StringUtils.isEmpty(pub) ? null : pub;
    priv = StringUtils.isEmpty(priv) ? null : priv;
    if (pub == null || priv == null) {
      throw new ValidationException("error.missing_ca_credentials");
    }
    return new CertificateAuthority(type, pub, priv);
  }

  @Override
  public NamedCertificateAuthority makeEntity(String name) {
    return new NamedCertificateAuthority(name);
  }
}