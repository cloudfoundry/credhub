package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.entity.*;
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

  @Autowired
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Autowired
  SshGeneratorRequestTranslator sshGeneratorRequestTranslator;

  @Autowired
  RsaGeneratorRequestTranslator rsaGeneratorRequestTranslator;

  @Override
  public SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsed) {
    return new SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException>() {
      @Override
      public NamedSecret value(NamedSecret namedSecret) {
        throw new ParameterizedValidationException("error.invalid_generate_type");
      }

      @Override
      public NamedSecret password(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return processSecret((NamedPasswordSecret) namedSecret, NamedPasswordSecret::new, secretPath, passwordGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret certificate(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return processSecret((NamedCertificateSecret) namedSecret, NamedCertificateSecret::new, secretPath, certificateGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret ssh(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return processSecret((NamedSshSecret) namedSecret, NamedSshSecret::new, secretPath, sshGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret rsa(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return processSecret((NamedRsaSecret) namedSecret, NamedRsaSecret::new, secretPath, rsaGeneratorRequestTranslator, parsed);
      }
    };
  }
}
