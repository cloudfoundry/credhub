package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.CertificateSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.function.Supplier;

import io.pivotal.security.view.ParameterizedValidationException;

@Component
public class CertificateGeneratorRequestTranslator implements RequestTranslator<NamedCertificateSecret>, SecretGeneratorRequestTranslator<CertificateSecretParameters> {

  @Autowired
  SecretGenerator<CertificateSecretParameters, CertificateSecret> certificateSecretGenerator;

  private Supplier<CertificateSecretParameters> parametersSupplier = CertificateSecretParameters::new;

  public CertificateSecretParameters validRequestParameters(DocumentContext parsed) {
    CertificateSecretParameters secretParameters = validCertificateAuthorityParameters(parsed);

    Optional.ofNullable(parsed.read("$.parameters.alternative_names", String[].class))
        .ifPresent(secretParameters::addAlternativeNames);
    Optional.ofNullable(parsed.read("$.parameters.ca", String.class))
        .ifPresent(secretParameters::setCa);

    secretParameters.validate();

    return secretParameters;
  }

  public CertificateSecretParameters validCertificateAuthorityParameters(DocumentContext parsed) {
    CertificateSecretParameters secretParameters = parametersSupplier.get();
    Optional.ofNullable(parsed.read("$.parameters.common_name", String.class))
        .ifPresent(secretParameters::setCommonName);
    Optional.ofNullable(parsed.read("$.parameters.organization", String.class))
        .ifPresent(secretParameters::setOrganization);
    Optional.ofNullable(parsed.read("$.parameters.organization_unit", String.class))
        .ifPresent(secretParameters::setOrganizationUnit);
    Optional.ofNullable(parsed.read("$.parameters.locality", String.class))
        .ifPresent(secretParameters::setLocality);
    Optional.ofNullable(parsed.read("$.parameters.state", String.class))
        .ifPresent(secretParameters::setState);
    Optional.ofNullable(parsed.read("$.parameters.country", String.class))
        .ifPresent(secretParameters::setCountry);
    Optional.ofNullable(parsed.read("$.parameters.key_length", Integer.class))
        .ifPresent(secretParameters::setKeyLength);
    Optional.ofNullable(parsed.read("$.parameters.duration", Integer.class))
        .ifPresent(secretParameters::setDurationDays);

    secretParameters.setType(parsed.read("$.type", String.class));

    secretParameters.validate();

    return secretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedCertificateSecret entity, DocumentContext documentContext) {
    CertificateSecretParameters requestParameters = validRequestParameters(documentContext);
    CertificateSecret secret = certificateSecretGenerator.generateSecret(requestParameters);
    entity.setCa(secret.getCertificateBody().getCa());
    entity.setCertificate(secret.getCertificateBody().getCertificate());
    entity.setPrivateKey(secret.getCertificateBody().getPrivateKey());
  }

  void setParametersSupplier(Supplier<CertificateSecretParameters> parametersSupplier) {
    this.parametersSupplier = parametersSupplier;
  }
}