package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.CertificateAuthorityBody;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.pivotal.security.view.ParameterizedValidationException;

@Component
public class CAGeneratorRequestTranslator implements RequestTranslator<NamedCertificateAuthority> {
  @Autowired
  BCCertificateGenerator certificateGenerator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  public CertificateAuthority createAuthorityFromJson(DocumentContext parsed) {
    if (!"root".equals(parsed.read("$.type"))) {
      throw new ParameterizedValidationException("error.bad_authority_type");
    }

    CertificateSecretParameters parameters =
        certificateGeneratorRequestTranslator.validCertificateAuthorityParameters(parsed);

    try {
      return certificateGenerator.generateCertificateAuthority(parameters);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void populateEntityFromJson(NamedCertificateAuthority namedCA, DocumentContext documentContext) {
    if (!"root".equals(documentContext.read("$.type"))) {
      throw new ParameterizedValidationException("error.bad_authority_type");
    }

    CertificateSecretParameters parameters =
        certificateGeneratorRequestTranslator.validCertificateAuthorityParameters(documentContext);

    CertificateAuthority certificateAuthority;

    try {
      certificateAuthority = certificateGenerator.generateCertificateAuthority(parameters);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    CertificateAuthorityBody caBody = certificateAuthority.getCertificateAuthorityBody();
    namedCA
        .setType(certificateAuthority.getType())
        .setCertificate(caBody.getCertificate())
        .setPrivateKey(caBody.getPrivateKey());
  }
}
