package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.PasswordSetRequestTranslator;
import io.pivotal.security.mapper.ValueSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import static com.greghaskins.spectrum.Spectrum.describe;

@RunWith(Spectrum.class)
public class NamedSecretSetHandlerTest extends NamedSecretHandlerTest {

  @InjectMocks
  NamedSecretSetHandler subject;

  @Mock
  ValueSetRequestTranslator valueSetRequestTranslator;

  @Mock
  PasswordSetRequestTranslator passwordSetRequestTranslator;

  @Mock
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  {
    describe("when mapping a value, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.valueSetRequestTranslator, SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret(), new NamedValueSecret()));

    describe("when mapping a password, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.passwordSetRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

    describe("when mapping a certificate, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.certificateSetRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));
  }
}