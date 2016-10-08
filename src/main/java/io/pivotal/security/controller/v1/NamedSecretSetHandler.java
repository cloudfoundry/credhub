package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.*;
import io.pivotal.security.mapper.*;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class NamedSecretSetHandler implements SecretKindMappingFactory {

  @Autowired
  StringSetRequestTranslator stringSetRequestTranslator;

  @Autowired
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  @Autowired
  RsaSshSetRequestTranslator rsaSshSetRequestTranslator;

  @Override
  public SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed) {
    return new SecretKind.Mapping<NamedSecret, NamedSecret>() {
      @Override
      public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedValueSecret)namedSecret, NamedValueSecret::new, secretPath, stringSetRequestTranslator, parsed);
      }

      @Override
      public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedPasswordSecret)namedSecret, NamedPasswordSecret::new, secretPath, stringSetRequestTranslator, parsed);
      }

      @Override
      public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedCertificateSecret)namedSecret, NamedCertificateSecret::new, secretPath, certificateSetRequestTranslator, parsed);
      }

      @Override
      public NamedSecret ssh(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedSshSecret)namedSecret, NamedSshSecret::new, secretPath, rsaSshSetRequestTranslator, parsed);
      }

      @Override
      public NamedSecret rsa(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedRsaSecret)namedSecret, NamedRsaSecret::new, secretPath, rsaSshSetRequestTranslator, parsed);
      }
    }.compose(new ValidateTypeMatch());
  }
}
