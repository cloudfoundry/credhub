package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.RequestTranslator;
import io.pivotal.security.mapper.ValueGeneratorRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import javax.validation.ValidationException;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
public class NamedSecretGenerateHandlerTest {

  @InjectMocks
  NamedSecretGenerateHandler subject;

  @Mock
  ValueGeneratorRequestTranslator valueGeneratorRequestTranslator;

  @Mock
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  @Mock
  DocumentContext documentContext;

  NamedSecret existingEntity;

  RequestTranslator expectedTranslator;

  {
    beforeEach(injectMocks(this));

    describe("when mapping a value", () -> {
      beforeEach(() -> {
        existingEntity = new NamedValueSecret();
        expectedTranslator = subject.valueGeneratorRequestTranslator;
      });

      describe("it behaves like a mapper", behavesLikeMapper(SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret()));
    });

    describe("when mapping a password", () -> {
      beforeEach(() -> {
        existingEntity = new NamedPasswordSecret();
        expectedTranslator = subject.passwordGeneratorRequestTranslator;
      });

      describe("it behaves like a mapper", behavesLikeMapper(SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret()));
    });

    describe("when mapping a certificate", () -> {
      beforeEach(() -> {
        existingEntity = new NamedCertificateSecret();
        expectedTranslator = subject.certificateGeneratorRequestTranslator;
      });

      describe("it behaves like a mapper", behavesLikeMapper(SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret()));
    });
  }

  private Block behavesLikeMapper(SecretKind secretKind, Class<? extends NamedSecret> clazz, NamedSecret mistypedSecret) {
    return () -> {
      itThrowsWithMessage("checks the type", ValidationException.class, "error.type_mismatch", () -> {
        secretKind.map(subject.make("secret-path", documentContext)).apply(mistypedSecret);
      });

      it("creates the secret", () -> {
        NamedSecret namedSecret = secretKind.map(subject.make("secret-path", documentContext)).apply(null);
        verify(expectedTranslator).populateEntityFromJson(isA(clazz), eq(documentContext));
        assertThat(namedSecret, instanceOf(clazz));
        assertThat(namedSecret.getName(), equalTo("secret-path"));
      });

      it("updates the secret", () -> {
        NamedSecret namedSecret = secretKind.map(subject.make("secret-path", documentContext)).apply(existingEntity);
        verify(expectedTranslator).populateEntityFromJson(existingEntity, documentContext);
        assertThat(namedSecret, sameInstance(existingEntity));
      });
    };
  }
}