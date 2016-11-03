package io.pivotal.security.mapper;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

import static com.google.common.collect.ImmutableSet.of;
import static io.pivotal.security.util.StringUtil.INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@Component
public class CertificateGeneratorRequestTranslator implements RequestTranslator<NamedCertificateSecret>, SecretGeneratorRequestTranslator<CertificateSecretParameters, NamedCertificateSecret> {

  @Autowired
  SecretGenerator<CertificateSecretParameters, CertificateSecret> certificateSecretGenerator;

  @Autowired
  CertificateSecretParametersFactory parametersFactory;

  @Override
  public CertificateSecretParameters validRequestParameters(DocumentContext parsed, NamedCertificateSecret entity) {
    Boolean regenerate = parsed.read("$.regenerate", Boolean.class);

    if (Boolean.TRUE.equals(regenerate)) {
      if (isEmpty(entity.getCaName())) {
        throw new ParameterizedValidationException("error.cannot_regenerated_non_generated_credentials");
      }
      return new CertificateSecretParameters(entity.getCertificate())
          .setCaName(entity.getCaName())
          .setDurationDays(entity.getDurationDays())
          .setKeyLength(entity.getKeyLength())
          .addAlternativeNames(entity.getAlternativeNames());
    }

    CertificateSecretParameters secretParameters = validCertificateAuthorityParameters(parsed);

    Optional.ofNullable(parsed.read("$.parameters.alternative_names", String[].class))
        .ifPresent(secretParameters::addAlternativeNames);
    Optional.ofNullable(parsed.read("$.parameters.ca", String.class))
        .ifPresent(secretParameters::setCaName);

    secretParameters.validate();

    return secretParameters;
  }

  public CertificateSecretParameters validCertificateAuthorityParameters(DocumentContext parsed) {
    CertificateSecretParameters secretParameters = parametersFactory.get();
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
    CertificateSecretParameters requestParameters = validRequestParameters(documentContext, entity);
    CertificateSecret secret = certificateSecretGenerator.generateSecret(requestParameters);
    entity.setCa(secret.getCertificateBody().getCa());
    entity.setCertificate(secret.getCertificateBody().getCertificate());
    entity.setPrivateKey(secret.getCertificateBody().getPrivateKey());
    entity.setCaName(requestParameters.getCaName());
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['type']",
        "$['overwrite']",
        "$['regenerate']",
        "$['parameters']",
        "$['parameters']['alternative_names']",
        "$['parameters']['alternative_names']" + INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS,
        "$['parameters']['ca']",
        "$['parameters']['common_name']",
        "$['parameters']['organization']",
        "$['parameters']['organization_unit']",
        "$['parameters']['locality']",
        "$['parameters']['state']",
        "$['parameters']['country']",
        "$['parameters']['key_length']",
        "$['parameters']['duration']"
    );
  }
}
