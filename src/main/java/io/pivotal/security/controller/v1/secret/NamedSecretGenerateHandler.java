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
  public SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException>() {
      @Override
      public NamedSecret value(NamedSecret namedSecret) {
        throw new ParameterizedValidationException("error.invalid_generate_type");
      }

      @Override
      public NamedSecret password(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedPasswordSecret) namedSecret, NamedPasswordSecret::new, secretPath, passwordGeneratorRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecret certificate(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedCertificateSecret) namedSecret, NamedCertificateSecret::new, secretPath, certificateGeneratorRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecret ssh(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedSshSecret) namedSecret, NamedSshSecret::new, secretPath, sshGeneratorRequestTranslator, parsedRequest);
      }

      @Override
      public NamedSecret rsa(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedRsaSecret) namedSecret, NamedRsaSecret::new, secretPath, rsaGeneratorRequestTranslator, parsedRequest);
      }
    };
  }
}
