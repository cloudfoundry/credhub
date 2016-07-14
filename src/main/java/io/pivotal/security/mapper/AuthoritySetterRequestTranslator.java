package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedAuthority;
import io.pivotal.security.view.CertificateAuthority;

public interface AuthoritySetterRequestTranslator {
  CertificateAuthority createAuthorityFromJson(DocumentContext documentContext);

  NamedAuthority makeEntity(String name);
}