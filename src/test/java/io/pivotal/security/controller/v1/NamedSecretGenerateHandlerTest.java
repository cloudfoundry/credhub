package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.ValueGeneratorRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import static com.greghaskins.spectrum.Spectrum.describe;

@RunWith(Spectrum.class)
public class NamedSecretGenerateHandlerTest extends NamedSecretHandlerTest {

  @InjectMocks
  NamedSecretGenerateHandler subject;

  @Mock
  ValueGeneratorRequestTranslator valueGeneratorRequestTranslator;

  @Mock
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  {
    describe("when mapping a value, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.valueGeneratorRequestTranslator, SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret(), new NamedValueSecret()));

    describe("when mapping a password, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.passwordGeneratorRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

    describe("when mapping a certificate, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.certificateGeneratorRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));
  }
}