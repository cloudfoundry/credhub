package org.cloudfoundry.credhub.service.regeneratables;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import org.bouncycastle.asn1.x509.GeneralName;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters;
import org.cloudfoundry.credhub.utils.CertificateReader;

import static org.apache.commons.lang3.StringUtils.isEmpty;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.CRL_SIGN;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.KEY_CERT_SIGN;

@Component
public class CertificateCredentialRegeneratable implements Regeneratable {

  private final boolean defaultCAKeyUsages;

  public CertificateCredentialRegeneratable(
          @Value("${certificates.enable_default_ca_key_usages:false}") boolean defaultCAKeyUsages
  ) {
    this.defaultCAKeyUsages = defaultCAKeyUsages;
  }

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(final CredentialVersion credentialVersion) {
    final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) credentialVersion;
    final CertificateReader reader = certificateCredential.getParsedCertificate();

    if (isEmpty(certificateCredential.getCaName()) && !reader.isSelfSigned()) {
      throw new ParameterizedValidationException(
              ErrorMessages.CANNOT_REGENERATE_NON_GENERATED_CERTIFICATE);
    }

    final CertificateGenerationRequestParameters requestParameters =
            buildRequestParametersFromReader(reader, certificateCredential);

    if (defaultCAKeyUsages && certificateCredential.isCertificateAuthority()) {
      if (reader.getKeyUsage() == null) {
        requestParameters.setKeyUsage(new String[]{KEY_CERT_SIGN, CRL_SIGN});
      }
    }

    final CertificateGenerationParameters certificateGenerationParameters =
            new CertificateGenerationParameters(requestParameters);

    final CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateCredential.getName());
    generateRequest.setType(certificateCredential.getCredentialType());
    generateRequest.setCertificateGenerationParameters(certificateGenerationParameters);
    generateRequest.setOverwrite(true);
    return generateRequest;
  }

  private CertificateGenerationRequestParameters buildRequestParametersFromReader(
          CertificateReader reader,
          CertificateCredentialVersion credentialVersion
  ) {
    CertificateGenerationRequestParameters params = new CertificateGenerationRequestParameters();

    String[] alternativeNames = null;
    if (reader.getAlternativeNames() != null) {
      alternativeNames = Arrays.stream(reader.getAlternativeNames().getNames())
              .map(GeneralName::toString)
              .toArray(String[]::new);
    }

    params.setCommonName(reader.getCommonName());
    params.setOrganization(reader.getOrganization());
    params.setOrganizationUnit(reader.getOrganizationUnit());
    params.setLocality(reader.getLocality());
    params.setState(reader.getState());
    params.setCountry(reader.getCountry());
    params.setKeyLength(reader.getKeyLength());
    params.setDuration(reader.getDurationDays());
    params.setCa(reader.isCa());
    params.setSelfSigned(reader.isSelfSigned());
    params.setCaName(credentialVersion.getCaName());
    params.setAlternativeNames(alternativeNames);
    params.setExtendedKeyUsage(reader.getExtendedKeyUsageStrings());
    params.setKeyUsage(reader.getKeyUsageStrings());
    return params;
  }
}
