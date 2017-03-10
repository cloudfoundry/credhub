package io.pivotal.security.controller.v1.secret;

import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.controller.v1.SecretKindMappingFactory;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.RsaSetRequestTranslator;
import io.pivotal.security.mapper.SshSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
class NamedSecretSetHandler implements SecretKindMappingFactory {
  private final CertificateSetRequestTranslator certificateSetRequestTranslator;
  private final SshSetRequestTranslator sshSetRequestTranslator;
  private final RsaSetRequestTranslator rsaSetRequestTranslator;
  private final Encryptor encryptor;

  @Autowired
  public NamedSecretSetHandler(
    CertificateSetRequestTranslator certificateSetRequestTranslator,
    SshSetRequestTranslator sshSetRequestTranslator,
    RsaSetRequestTranslator rsaSetRequestTranslator,
    Encryptor encryptor
  ) {
    this.certificateSetRequestTranslator = certificateSetRequestTranslator;
    this.sshSetRequestTranslator = sshSetRequestTranslator;
    this.rsaSetRequestTranslator = rsaSetRequestTranslator;
    this.encryptor = encryptor;
  }

  @Override
  public SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException> make(String secretPath, DocumentContext parsedRequest) {
    return new SecretKind.CheckedMapping<NamedSecret, NoSuchAlgorithmException>() {
      @Override
      public NamedSecret value(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException();
      }

      @Override
      public NamedSecret password(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException();
      }

      @Override
      public NamedSecret certificate(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedCertificateSecret) namedSecret, NamedCertificateSecret::new, secretPath, certificateSetRequestTranslator, parsedRequest, encryptor);
      }

      @Override
      public NamedSecret ssh(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedSshSecret) namedSecret, NamedSshSecret::new, secretPath, sshSetRequestTranslator, parsedRequest, encryptor);
      }

      @Override
      public NamedSecret rsa(NamedSecret namedSecret) throws NoSuchAlgorithmException {
        return createNewSecret((NamedRsaSecret) namedSecret, NamedRsaSecret::new, secretPath, rsaSetRequestTranslator, parsedRequest, encryptor);
      }
    };
  }
}
