package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.model.CertificateSecretParameters;
import io.pivotal.security.model.GeneratorRequest;
import org.springframework.stereotype.Component;

import javax.validation.ValidationException;
import java.util.Optional;

@Component
public class CertificateGeneratorRequestTranslator implements SecretGeneratorRequestTranslator {
  public GeneratorRequest<CertificateSecretParameters> validGeneratorRequest(DocumentContext parsed) throws ValidationException {
    GeneratorRequest<CertificateSecretParameters> generatorRequest = new GeneratorRequest<>();
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
    Optional.ofNullable(parsed.read("$.parameters.alternate_name", String[].class))
        .ifPresent(secretParameters::addAlternateNames);
    generatorRequest.setType(parsed.read("$.type"));
    generatorRequest.setParameters(secretParameters);
    if (!secretParameters.isValid()) {
      throw new ValidationException("error.missing_certificate_parameters");
    }

    return generatorRequest;
  }
}