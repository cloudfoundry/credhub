package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.mapper.CertificateGeneratorRequestTranslator;
import io.pivotal.security.mapper.PasswordGeneratorRequestTranslator;
import io.pivotal.security.mapper.ValueGeneratorRequestTranslator;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;

public class NamedSecretGenerateHandlerTest extends NamedSecretHandlerTest {

  @InjectMocks
  NamedSecretGenerateHandler subject;

  @Autowired
  NamedSecretGenerateHandler realSubject;

  @Autowired
  Configuration configuration;

  @Mock
  SecretGenerator certificateSecretGenerator;

  @Mock
  ValueGeneratorRequestTranslator valueGeneratorRequestTranslator;

  @Mock
  PasswordGeneratorRequestTranslator passwordGeneratorRequestTranslator;

  @Mock
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  {
    describe("mocked", () -> {
      beforeEach(injectMocks(this));

      describe("when mapping a value, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.valueGeneratorRequestTranslator, SecretKind.VALUE, NamedValueSecret.class, new NamedCertificateSecret(), new NamedValueSecret()));

      describe("when mapping a password, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.passwordGeneratorRequestTranslator, SecretKind.PASSWORD, NamedPasswordSecret.class, new NamedValueSecret(), new NamedPasswordSecret()));

      describe("when mapping a certificate, it behaves like a mapper", behavesLikeMapper(() -> subject, () -> subject.certificateGeneratorRequestTranslator, SecretKind.CERTIFICATE, NamedCertificateSecret.class, new NamedPasswordSecret(), new NamedCertificateSecret()));
    });

    describe("not mocked", () -> {
      wireAndUnwire(this);

      it("value", () -> {
        String requestJson = "{\"type\":\"value\",\"parameters\":{\"length\":2048,\"exclude_lower\":true,\"exclude_upper\":false,\"exclude_number\":false,\"exclude_special\":false}}";
        final DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
        realSubject.make("name", parsed).value(SecretKind.VALUE, null);
        // no exception
      });

      it("password", () -> {
        String requestJson = "{\"type\":\"password\",\"parameters\":{\"length\":2048,\"exclude_lower\":true,\"exclude_upper\":false,\"exclude_number\":false,\"exclude_special\":false}}";
        final DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
        realSubject.make("name", parsed).password(SecretKind.PASSWORD, null);
        // no exception
      });

      it("certificate", () -> {
        String requestJson = "{" +
            "\"type\":\"certificate\"," +
            "\"parameters\":{" +
            "\"common_name\":\"My Common Name\", " +
            "\"organization\": \"organization.io\"," +
            "\"organization_unit\": \"My Unit\"," +
            "\"locality\": \"My Locality\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"key_length\": 3072," +
            "\"duration\": 1000," +
            "\"alternative_names\": []," +
            "\"ca\": \"default\"," +
            "}" +
            "}";
        final DocumentContext parsed = JsonPath.using(configuration).parse(requestJson);
        realSubject.make("default", parsed).certificate(SecretKind.CERTIFICATE, null);
        // no exception
      });
    });
  }
}