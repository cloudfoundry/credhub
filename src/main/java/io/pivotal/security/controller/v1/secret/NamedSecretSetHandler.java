package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.PasswordSetRequestTranslator;
import io.pivotal.security.mapper.RsaSshSetRequestTranslator;
import io.pivotal.security.mapper.ValueSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
class NamedSecretSetHandler implements SecretKindMappingFactory {
  private final ValueSetRequestTranslator valueSetRequestTranslator;
  private final PasswordSetRequestTranslator passwordSetRequestTranslator;
  private final CertificateSetRequestTranslator certificateSetRequestTranslator;
  private final RsaSshSetRequestTranslator rsaSshSetRequestTranslator;
  private final Encryptor encryptor;

  @Autowired
  public NamedSecretSetHandler(
      ValueSetRequestTranslator valueSetRequestTranslator,
      PasswordSetRequestTranslator passwordSetRequestTranslator,
      CertificateSetRequestTranslator certificateSetRequestTranslator,
      RsaSshSetRequestTranslator rsaSshSetRequestTranslator,
      Encryptor encryptor
  ) {
    this.valueSetRequestTranslator = valueSetRequestTranslator;
    this.passwordSetRequestTranslator = passwordSetRequestTranslator;
    this.certificateSetRequestTranslator = certificateSetRequestTranslator;
    this.rsaSshSetRequestTranslator = rsaSshSetRequestTranslator;
    this.encryptor = encryptor;
  }

  @Override
  public SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException>() {
      @Override
      public NamedSecret value(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedValueSecret) namedSecret, NamedValueSecret::new, secretPath, valueSetRequestTranslator, parsedRequest, encryptor);
      }

      @Override
      public NamedSecret password(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedPasswordSecret) namedSecret, NamedPasswordSecret::new, secretPath, passwordSetRequestTranslator, parsedRequest, encryptor);
      }

      @Override
      public NamedSecret certificate(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedCertificateSecret) namedSecret, NamedCertificateSecret::new, secretPath, certificateSetRequestTranslator, parsedRequest, encryptor);
      }

      @Override
      public NamedSecret ssh(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedSshSecret) namedSecret, NamedSshSecret::new, secretPath, rsaSshSetRequestTranslator, parsedRequest, encryptor);
      }

      @Override
      public NamedSecret rsa(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedRsaSecret) namedSecret, NamedRsaSecret::new, secretPath, rsaSshSetRequestTranslator, parsedRequest, encryptor);
      }
    };
  }
}
