package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedSecret;
import org.springframework.stereotype.Component;

import javax.validation.ValidationException;
import java.util.Optional;

@Component
public class CertificateGeneratorRequestTranslator implements SecretGeneratorRequestTranslator<CertificateSecretParameters> {
  public CertificateSecretParameters validRequestParameters(DocumentContext parsed) throws ValidationException {
    CertificateSecretParameters secretParameters = new CertificateSecretParameters();
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
    Optional.ofNullable(parsed.read("$.parameters.alternative_name", String[].class))
        .ifPresent(secretParameters::addAlternativeNames);
    Optional.ofNullable(parsed.read("$.parameters.key_length", Integer.class))
        .ifPresent(secretParameters::setKeyLength);
    Optional.ofNullable(parsed.read("$.parameters.duration", Integer.class))
        .ifPresent(secretParameters::setDurationDays);
    Optional.ofNullable(parsed.read("$.parameters.ca", String.class))
        .ifPresent(secretParameters::setCa);
    String certType = parsed.read("$.type", String.class);
    Optional.ofNullable(certType).ifPresent(secretParameters::setType);

    secretParameters.validate();

    return secretParameters;
  }

  @Override
  public NamedSecret makeEntity(String name) {
    return new NamedCertificateSecret(name);
  }
}