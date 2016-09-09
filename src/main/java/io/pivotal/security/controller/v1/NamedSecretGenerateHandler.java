package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.ValueGeneratorRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class NamedSecretGenerateHandler implements SecretKindMappingFactory {

  @Autowired
  ValueGeneratorRequestTranslator valueGeneratorRequestTranslator;

  @Autowired
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Autowired
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Override
  public SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed) {
    return new SecretKind.Mapping<NamedSecret, NamedSecret>() {
      @Override
      public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedValueSecret)namedSecret, NamedValueSecret::new, secretPath, valueGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedPasswordSecret)namedSecret, NamedPasswordSecret::new, secretPath, passwordGeneratorRequestTranslator, parsed);
      }

      @Override
      public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
        return processSecret((NamedCertificateSecret)namedSecret, NamedCertificateSecret::new, secretPath, certificateGeneratorRequestTranslator, parsed);
      }
    }.compose(new ValidateTypeMatch());
  }
}
