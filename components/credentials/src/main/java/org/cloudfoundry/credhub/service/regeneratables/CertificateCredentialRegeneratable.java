package org.cloudfoundry.credhub.service.regeneratables;

import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.BaseCredentialGenerateRequest;
import org.cloudfoundry.credhub.requests.CertificateGenerateRequest;
import org.cloudfoundry.credhub.utils.CertificateReader;

import static org.apache.commons.lang3.StringUtils.isEmpty;

public class CertificateCredentialRegeneratable implements Regeneratable {

  @Override
  public BaseCredentialGenerateRequest createGenerateRequest(final CredentialVersion credentialVersion) {
    final CertificateCredentialVersion certificateCredential = (CertificateCredentialVersion) credentialVersion;
    final CertificateReader reader = certificateCredential.getParsedCertificate();

    if (isEmpty(certificateCredential.getCaName()) && !reader.isSelfSigned()) {
      throw new ParameterizedValidationException(
        ErrorMessages.CANNOT_REGENERATE_NON_GENERATED_CERTIFICATE);
    }

    final CertificateGenerationParameters certificateGenerationParameters = new CertificateGenerationParameters(
      reader,
      certificateCredential.getCaName()
    );

    final CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateCredential.getName());
    generateRequest.setType(certificateCredential.getCredentialType());
    generateRequest.setCertificateGenerationParameters(certificateGenerationParameters);
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
