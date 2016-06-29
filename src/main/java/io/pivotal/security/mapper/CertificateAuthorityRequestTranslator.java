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
    String pub = parsed.read("$.root.public");
    String priv = parsed.read("$.root.private");
    pub = StringUtils.isEmpty(pub) ? null : pub;
    priv = StringUtils.isEmpty(priv) ? null : priv;
    return new CertificateAuthority(pub, priv);
  }

  @Override
  public NamedCertificateAuthority makeEntity(String name) {
    return new NamedCertificateAuthority(name);
  }
}