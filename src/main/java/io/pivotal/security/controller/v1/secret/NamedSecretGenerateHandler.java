package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.RsaGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
class NamedSecretGenerateHandler implements SecretKindMappingFactory {
  private final PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;
  private final CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;
  private final SshGeneratorRequestTranslator sshGeneratorRequestTranslator;
  private final RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator;
  private final Encryptor encryptor;

  @Autowired
  NamedSecretGenerateHandler(
      PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator,
      CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator,
      SshGeneratorRequestTranslator sshGeneratorRequestTranslator,
      RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator,
      Encryptor encryptor
  ) {
    this.passwordGeneratorRequestTranslator = passwordGeneratorRequestTranslator;
    this.certificateGeneratorRequestTranslator = certificateGeneratorRequestTranslator;
    this.sshGeneratorRequestTranslator = sshGeneratorRequestTranslator;
    this.rsaGeneratorRequestTranslator = rsaGeneratorRequestTranslator;
    this.encryptor = encryptor;
  }

  @Override
  public SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException>() {
      @Override
      public NamedSecret value(NamedSecret namedSecret) {
        throw new ParameterizedValidationException("error.invalid_generate_type");
      }

      @Override
      public NamedSecret password(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedPasswordSecret) namedSecret, NamedPasswordSecret::new, secretPath, passwordGeneratorRequestTranslator, parsedRequest, encryptor, true);
      }

      @Override
      public NamedSecret certificate(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedCertificateSecret) namedSecret, NamedCertificateSecret::new, secretPath, certificateGeneratorRequestTranslator, parsedRequest, encryptor, true);
      }

      @Override
      public NamedSecret ssh(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedSshSecret) namedSecret, NamedSshSecret::new, secretPath, sshGeneratorRequestTranslator, parsedRequest, encryptor, true);
      }

      @Override
      public NamedSecret rsa(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedRsaSecret) namedSecret, NamedRsaSecret::new, secretPath, rsaGeneratorRequestTranslator, parsedRequest, encryptor, true);
      }
    };
  }
}
