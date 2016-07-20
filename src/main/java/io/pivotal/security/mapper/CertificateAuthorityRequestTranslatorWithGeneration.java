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
  CertificateSecretParameters certificateSecretParameters;

  @Override
  public CertificateAuthority createAuthorityFromJson(DocumentContext parsed) {
    if (!parsed.read("$.type").equals("root")) {
      throw new ValidationException("error.bad_authority_type");
    }

    certificateSecretParameters.setCommonName(parsed.read("$.parameters.common_name"))
        .setOrganization(parsed.read("$.parameters.organization"))
        .setOrganizationUnit(parsed.read("$.parameters.organization_unit"))
        .setLocality(parsed.read("$.parameters.locality"))
        .setState(parsed.read("$.parameters.state"))
        .setCountry(parsed.read("$.parameters.country"))
        .setKeyLength(parsed.read("$.parameters.key_length"))
        .setDurationDays(parsed.read("$.parameters.duration"));

    certificateSecretParameters.validate();

    try {
      return certificateGenerator.generateCertificateAuthority(certificateSecretParameters);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
