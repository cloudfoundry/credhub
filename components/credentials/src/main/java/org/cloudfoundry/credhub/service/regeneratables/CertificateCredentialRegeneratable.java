package org.cloudfoundry.credhub.service.regeneratables;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest;
import org.cloudfoundry.credhub.utils.CertificateReader;

import static org.apache.commons.lang3.StringUtils.isEmpty;

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

    final CertificateGenerationParameters certificateGenerationParameters =
            new CertificateGenerationParameters(reader, certificateCredential.getCaName());

    if (defaultCAKeyUsages && certificateCredential.isCertificateAuthority()) {
      if (reader.getKeyUsage() == null) {
        certificateGenerationParameters.setKeyUsage(
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      }
    }

    final CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateCredential.getName());
    generateRequest.setType(certificateCredential.getCredentialType());
    generateRequest.setCertificateGenerationParameters(certificateGenerationParameters);
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
