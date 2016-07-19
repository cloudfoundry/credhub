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

  @Override
  public CertificateAuthority createAuthorityFromJson(DocumentContext parsed) {
    if (!parsed.read("$.type").equals("root")) {
      throw new ValidationException("error.bad_authority_type");
    }

    CertificateSecretParameters params = new CertificateSecretParameters()
        .setCommonName(parsed.read("$.parameters.common_name"))
        .setOrganization(parsed.read("$.parameters.organization"))
        .setOrganizationUnit(parsed.read("$.parameters.organization_unit"))
        .setLocality(parsed.read("$.parameters.locality"))
        .setState(parsed.read("$.parameters.state"))
        .setCountry(parsed.read("$.parameters.country"));

    try {
      return certificateGenerator.generateCertificateAuthority(params);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
