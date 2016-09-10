package io.pivotal.security.controller.v1;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.mapper.CertificateSetRequestTranslator;
import io.pivotal.security.mapper.PasswordSetRequestTranslator;
import io.pivotal.security.mapper.ValueSetRequestTranslator;
import io.pivotal.security.view.SecretKind;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;

public class NamedSecretSetHandlerTest extends NamedSecretHandlerTest {

  @InjectMocks
  NamedSecretSetHandler subject;

  @Autowired
  NamedSecretSetHandler realSubject;

  @Autowired
  Configuration configuration;

  @Mock
  ValueSetRequestTranslator valueSetRequestTranslator;

  @Mock
  PasswordSetRequestTranslator passwordSetRequestTranslator;

  @Mock
  CertificateSetRequestTranslator certificateSetRequestTranslator;

  {
    describe("mocked", () -> {
      beforeEach(injectMocks(this));

      describe("when mapping a value, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.valueSetRequestTranslator, SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret(), new NamedValueSecret()));

      describe("when mapping a password, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.passwordSetRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

      describe("when mapping a certificate, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.certificateSetRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));
    });

    describe("not mocked", () -> {
      wireAndUnwire(this);

      it("value", () -> {
        String requestJson = "{\"type\":\"value\",\"value\":\"myValue\"}";
        final DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
        realSubject.make("name", parsed).value(SecretKind.VALUE, null);
        // no exception
      });

      it("password", () -> {
        String requestJson = "{\"type\":\"password\",\"value\":\"myValue\"}";
        final DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
        realSubject.make("name", parsed).password(SecretKind.PASSWORD, null);
        // no exception
      });

      it("certificate", () -> {
        String requestJson = "{\"type\":\"certificate\",\"value\":{\"ca\":\"ca\",\"certificate\":\"cert\",\"private_key\":\"pk\"}}";
        final DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
        realSubject.make("name", parsed).certificate(SecretKind.CERTIFICATE, null);
        // no exception
      });
    });
  }
}