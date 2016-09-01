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
    //noinspection Duplicates
    return new SecretKind.Mapping<NamedSecret, NamedSecret>() {
      @Override
      public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
        NamedValueSecret namedValueSecret = namedSecret == null ? new NamedValueSecret(secretPath) : (NamedValueSecret) namedSecret;
        valueGeneratorRequestTranslator.populateEntityFromJson(namedValueSecret, parsed);
        return namedValueSecret;
      }

      @Override
      public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
        NamedPasswordSecret namedPasswordSecret = namedSecret == null ? new NamedPasswordSecret(secretPath) : (NamedPasswordSecret) namedSecret;
        passwordGeneratorRequestTranslator.populateEntityFromJson(namedPasswordSecret, parsed);
        return namedPasswordSecret;
      }

      @Override
      public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
        NamedCertificateSecret namedCertificateSecret = namedSecret == null ? new NamedCertificateSecret(secretPath) : (NamedCertificateSecret) namedSecret;
        certificateGeneratorRequestTranslator.populateEntityFromJson(namedCertificateSecret, parsed);
        return namedCertificateSecret;
      }
    }.compose(new ValidateTypeMatch());
  }
}
