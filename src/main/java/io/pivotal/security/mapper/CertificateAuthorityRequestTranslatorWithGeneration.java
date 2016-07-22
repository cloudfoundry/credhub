package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.view.CertificateAuthority;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.validation.ValidationException;

@Component
public class CertificateAuthorityRequestTranslatorWithGeneration implements AuthoritySetterRequestTranslator {
  @Autowired
  BCCertificateGenerator certificateGenerator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Override
  public CertificateAuthority createAuthorityFromJson(DocumentContext parsed) {
    if (!"root".equals(parsed.read("$.type"))) {
      throw new ValidationException("error.bad_authority_type");
    }

    CertificateSecretParameters parameters =
        certificateGeneratorRequestTranslator.validCertificateAuthorityParameters(parsed);

    try {
      return certificateGenerator.generateCertificateAuthority(parameters);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
