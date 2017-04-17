package io.pivotal.security.service.regeneratables;

import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.BaseSecretGenerateRequest;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.util.CertificateReader;

import static org.apache.commons.lang3.StringUtils.isEmpty;

public class CertificateSecretRegeneratable implements Regeneratable {

  @Override
  public BaseSecretGenerateRequest createGenerateRequest(NamedSecret secret) {
    NamedCertificateSecret certificateSecret = (NamedCertificateSecret) secret;
    CertificateReader reader = new CertificateReader(certificateSecret.getCertificate());

    if (!reader.isValid() || (isEmpty(certificateSecret.getCaName()) && !reader.isSelfSigned())) {
      throw new ParameterizedValidationException(
          "error.cannot_regenerate_non_generated_certificate");
    }

    CertificateParameters certificateParameters = new CertificateParameters(reader,
        certificateSecret.getCaName());

    CertificateGenerateRequest generateRequest = new CertificateGenerateRequest();
    generateRequest.setName(certificateSecret.getName());
    generateRequest.setType(certificateSecret.getSecretType());
    generateRequest.setCertificateParameters(certificateParameters);
    generateRequest.setOverwrite(true);
    return generateRequest;
  }
}
