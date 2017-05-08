package io.pivotal.security.domain;

import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.request.CertificateGenerationParameters;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.RsaGenerateRequest;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserGenerateRequest;
import io.pivotal.security.service.GeneratorService;

public class CredentialValueFactory {

  public static CredentialValue generateValue(BaseCredentialGenerateRequest requestBody,
      GeneratorService generatorService) {
    CredentialValue credentialValue;

    switch (requestBody.getType()) {
      case "password":
        final StringGenerationParameters stringGenerationParameters = ((PasswordGenerateRequest) requestBody)
            .getGenerationParameters();
        credentialValue = generatorService.generatePassword(stringGenerationParameters);
        break;
      case "certificate":
        final CertificateGenerateRequest certificateRequest = (CertificateGenerateRequest) requestBody;
        if (certificateRequest.getCertificateParameters() == null) {
          final CertificateGenerationParameters certificateGenerationParameters = certificateRequest
              .getGenerationParameters();
          credentialValue = generatorService
              .generateCertificate(new CertificateParameters(certificateGenerationParameters));
        } else {
          credentialValue = generatorService
              .generateCertificate(certificateRequest.getCertificateParameters());
        }
        break;
      case "rsa":
        final RsaGenerationParameters rsaGenerationParameters = ((RsaGenerateRequest) requestBody)
            .getGenerationParameters();
        credentialValue = generatorService.generateRsaKeys(rsaGenerationParameters);
        break;
      case "ssh":
        final SshGenerationParameters sshGenerationParameters = ((SshGenerateRequest) requestBody)
            .getGenerationParameters();
        credentialValue = generatorService.generateSshKeys(sshGenerationParameters);
        break;
      case "user":
        final StringGenerationParameters userGenerationParameters = ((UserGenerateRequest) requestBody)
            .getPasswordGenerationParameters();
        final String userName = ((UserGenerateRequest) requestBody).getUserName();
        credentialValue = generatorService.generateUser(userName, userGenerationParameters);
        break;
      default:
        throw new RuntimeException("Non generated type: " + requestBody.getType());
    }
    return credentialValue;
  }
}
