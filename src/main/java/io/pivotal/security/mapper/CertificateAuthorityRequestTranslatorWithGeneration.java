package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedAuthority;
import io.pivotal.security.view.CertificateAuthority;
import org.springframework.stereotype.Component;

@Component
public class CertificateAuthorityRequestTranslatorWithGeneration implements AuthoritySetterRequestTranslator {
  @Override
  public CertificateAuthority createAuthorityFromJson(DocumentContext documentContext) {
    return null;
  }
}
