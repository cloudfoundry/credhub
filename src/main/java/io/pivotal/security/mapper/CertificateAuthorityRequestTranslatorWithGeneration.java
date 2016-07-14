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
    CertificateSecretParameters hardwiredParams = new CertificateSecretParameters()
        .setOrganization("Organization")
        .setState("CA")
        .setCountry("US")
        .setKeyLength(2048)
        .setDurationDays(365);
    return certificateGenerator.generateCertificateAuthority(hardwiredParams);
  }
}
