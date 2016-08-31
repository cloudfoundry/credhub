package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.PasswordSetRequestTranslator;
import io.pivotal.security.mapper.ValueSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.validation.ValidationException;

@Component
class NamedSecretSetHandler implements SecretKindMappingFactory {

  @Autowired
  ValueSetRequestTranslator valueSetRequestTranslator;

  @Autowired
  PasswordSetRequestTranslator passwordSetRequestTranslator;

  @Autowired
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  @Override
  public SecretKind.Mapping<NamedSecret, NamedSecret> make(String secretPath, DocumentContext parsed) {
    return new SecretKind.Mapping<NamedSecret, NamedSecret>() {
      @Override
      public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
        if (namedSecret != null && !(namedSecret instanceof NamedValueSecret)) throw new ValidationException("error.type_mismatch");

        NamedValueSecret namedValueSecret = namedSecret == null ? new NamedValueSecret(secretPath) : (NamedValueSecret) namedSecret;
        valueSetRequestTranslator.populateEntityFromJson(namedValueSecret, parsed);
        return namedValueSecret;
      }

      @Override
      public NamedSecret password(SecretKind secretKind, NamedSecret namedSecret) {
        if (namedSecret != null && !(namedSecret instanceof NamedPasswordSecret)) throw new ValidationException("error.type_mismatch");

        NamedPasswordSecret namedPasswordSecret = namedSecret == null ? new NamedPasswordSecret(secretPath) : (NamedPasswordSecret) namedSecret;
        passwordSetRequestTranslator.populateEntityFromJson(namedPasswordSecret, parsed);
        return namedPasswordSecret;
      }

      @Override
      public NamedSecret certificate(SecretKind secretKind, NamedSecret namedSecret) {
        if (namedSecret != null && !(namedSecret instanceof NamedCertificateSecret)) throw new ValidationException("error.type_mismatch");

        NamedCertificateSecret namedCertificateSecret = namedSecret == null ? new NamedCertificateSecret(secretPath) : (NamedCertificateSecret) namedSecret;
        certificateSetRequestTranslator.populateEntityFromJson(namedCertificateSecret, parsed);
        return namedCertificateSecret;
      }
    };
  }
}
