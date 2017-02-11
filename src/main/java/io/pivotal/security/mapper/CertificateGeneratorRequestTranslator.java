package io.pivotal.security.mapper;

import static com.google.common.collect.ImmutableSet.of;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.util.CertificateReader;
import static io.pivotal.security.util.StringUtil.INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS;
import io.pivotal.security.view.ParameterizedValidationException;
import org.apache.commons.lang3.StringUtils;
import static org.apache.commons.lang3.StringUtils.isEmpty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;

@Component
public class CertificateGeneratorRequestTranslator implements RequestTranslator<NamedCertificateSecret>, SecretGeneratorRequestTranslator<CertificateSecretParameters, NamedCertificateSecret> {

  private SecretGenerator<CertificateSecretParameters, Certificate> certificateSecretGenerator;
  private CertificateSecretParametersFactory parametersFactory;

  @Autowired
  public CertificateGeneratorRequestTranslator(
      SecretGenerator<CertificateSecretParameters, Certificate> certificateSecretGenerator,
      CertificateSecretParametersFactory parametersFactory) {
    this.certificateSecretGenerator = certificateSecretGenerator;
    this.parametersFactory = parametersFactory;
  }

  @Override
  public CertificateSecretParameters validRequestParameters(DocumentContext parsed, NamedCertificateSecret entity) {
    Boolean regenerate = parsed.read("$.regenerate", Boolean.class);

    if (Boolean.TRUE.equals(regenerate)) {
      CertificateReader certificateReader = new CertificateReader(entity.getCertificate());
      if (isEmpty(entity.getCaName()) && !certificateReader.isSelfSigned()) {
        throw new ParameterizedValidationException("error.cannot_regenerate_non_generated_credentials");
      }
      return new CertificateSecretParameters(certificateReader, entity.getCaName());
    }

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
    Optional.ofNullable(parsed.read("$.parameters.alternative_names", String[].class))
      .ifPresent(secretParameters::addAlternativeNames);
    Optional.ofNullable(parsed.read("$.parameters.key_usage", String[].class))
      .ifPresent(secretParameters::addKeyUsage);
    Optional.ofNullable(parsed.read("$.parameters.extended_key_usage", String[].class))
      .ifPresent(secretParameters::addExtendedKeyUsage);
    Optional.ofNullable(parsed.read("$.parameters.self_sign", Boolean.class))
      .ifPresent(secretParameters::setSelfSigned);
    Optional.ofNullable(parsed.read("$.parameters.is_ca", Boolean.class))
      .ifPresent(secretParameters::setIsCa);
    Optional.ofNullable(parsed.read("$.parameters.ca", String.class))
      .ifPresent(secretParameters::setCaName);

    if (secretParameters.isCA() && StringUtils.isEmpty(secretParameters.getCaName())) {
      secretParameters.setSelfSigned(true);
    }

    secretParameters.validate();

    return secretParameters;
  }

  @Override
  public void populateEntityFromJson(NamedCertificateSecret entity, DocumentContext documentContext) {
    CertificateSecretParameters requestParameters = validRequestParameters(documentContext, entity);

    Certificate secret = certificateSecretGenerator.generateSecret(requestParameters);
    entity.setCa(secret.getCaCertificate());
    entity.setCertificate(secret.getPublicKeyCertificate());
    entity.setPrivateKey(secret.getPrivateKey());
    entity.setCaName(requestParameters.getCaName());
  }

  @Override
  public Set<String> getValidKeys() {
    return of("$['type']",
        "$['name']",
        "$['overwrite']",
        "$['regenerate']",
        "$['parameters']",
        "$['parameters']['alternative_names']",
        "$['parameters']['alternative_names']"  + INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS,
        "$['parameters']['key_usage']",
        "$['parameters']['key_usage']" + INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS,
        "$['parameters']['extended_key_usage']",
        "$['parameters']['extended_key_usage']" + INTERNAL_SYMBOL_FOR_ALLOW_ARRAY_MEMBERS,
        "$['parameters']['ca']",
        "$['parameters']['common_name']",
        "$['parameters']['organization']",
        "$['parameters']['organization_unit']",
        "$['parameters']['locality']",
        "$['parameters']['state']",
        "$['parameters']['country']",
        "$['parameters']['key_length']",
        "$['parameters']['duration']",
        "$['parameters']['is_ca']",
        "$['parameters']['self_sign']"
    );
  }

}
