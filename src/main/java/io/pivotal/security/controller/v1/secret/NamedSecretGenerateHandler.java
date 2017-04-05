package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.view.SecretKind;
import java.security.NoSuchAlgorithmException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
class NamedSecretGenerateHandler implements SecretKindMappingFactory {

  private final CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;
  private final Encryptor encryptor;

  @Autowired
  NamedSecretGenerateHandler(
      CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator,
      Encryptor encryptor
  ) {
    this.certificateGeneratorRequestTranslator = certificateGeneratorRequestTranslator;
    this.encryptor = encryptor;
  }

  @Override
  public SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath,
      DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException>() {
      @Override
      public NamedSecret value(NamedSecret namedSecret) {
        throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
      }

      @Override
      public NamedSecret json(NamedSecret namedSecret) {
        throw new ParameterizedValidationException("error.invalid_type_with_generate_prompt");
      }

      @Override
      public NamedSecret certificate(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedCertificateSecret) namedSecret, NamedCertificateSecret::new,
            secretPath, certificateGeneratorRequestTranslator, parsedRequest, encryptor);
      }
    };
  }
}
