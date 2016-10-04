package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedSshSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.SshGeneratorRequestTranslator;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class NamedSecretGenerateHandler implements SecretKindMappingFactory {

  @Autowired
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Autowired
  SshGeneratorRequestTranslator sshGeneratorRequestTranslator;

  @Override
  public SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed) {
    return new SecretKind.Mapping<NamedSecret, NamedSecret>() {
      @Override
      public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
        throw new ParameterizedValidationException("error.invalid_generate_type");
      }

      @Override
      public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedPasswordSecret)namedSecret, NamedPasswordSecret::new, secretPath, passwordGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedCertificateSecret)namedSecret, NamedCertificateSecret::new, secretPath, certificateGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret ssh(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedSshSecret)namedSecret, NamedSshSecret::new, secretPath, sshGeneratorRequestTranslator, parsed);
      }
    }.compose(new ValidateTypeMatch() {
      @Override
      public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
        return namedSecret;
      }
    });
  }
}

