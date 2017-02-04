package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.config.JsonContextFactory;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.controller.v1.CertificateSecretParametersTest.TEST_CERT;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CertificateGeneratorRequestTranslatorTest {

  private CertificateGeneratorRequestTranslator subject;

  private BCCertificateGenerator certificateGenerator;
  private CertificateSecretParametersFactory certificateSecretParametersFactory;
  private ParseContext jsonPath;
  private DocumentContext parsed;
  private CertificateSecretParameters mockParams;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      certificateGenerator = mock(BCCertificateGenerator.class);
      certificateSecretParametersFactory = mock(CertificateSecretParametersFactory.class);
      subject = new CertificateGeneratorRequestTranslator(certificateGenerator, certificateSecretParametersFactory);

      when(certificateSecretParametersFactory.get()).thenCallRealMethod();

      jsonPath = new JsonContextFactory().getObject();
    });

    it("knows keys for all valid parameters", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"name\":\"My Name\"," +
          "\"regenerate\":false," +
          "\"overwrite\":false," +
          "\"parameters\":{" +
          "\"common_name\":\"My Common Name\", " +
          "\"organization\": \"organization.io\"," +
          "\"organization_unit\": \"My Unit\"," +
          "\"locality\": \"My Locality\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"key_length\": 3072," +
          "\"duration\": 1000," +
          "\"self_sign\": true," +
          "\"alternative_names\": [\"my-alternative-name-1\", \"my-alternative-name-2\"]," +
          "\"extended_key_usage\": [\"server_auth\", \"client_auth\"]," +
          "\"key_usage\": [\"data_encipherment\", \"non_repudiation\"]," +
          "\"ca\": \"My Ca\"" +
          "}" +
          "}";
      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setCommonName("My Common Name");
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setOrganizationUnit("My Unit");
      expectedParameters.setLocality("My Locality");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setType("certificate");
      expectedParameters.setDurationDays(1000);
      expectedParameters.setKeyLength(3072);
      expectedParameters.setSelfSign(true);
      expectedParameters.addAlternativeNames("my-alternative-name-1", "my-alternative-name-2");
      expectedParameters.addExtendedKeyUsage("server_auth", "client_auth");
      expectedParameters.addKeyUsage("data_encipherment", "non_repudiation");
      expectedParameters.setCaName("My Ca");
      expectedParameters.setIsCa(false);
      DocumentContext parsed = jsonPath.parse(json);

      subject.validateJsonKeys(parsed);
      CertificateSecretParameters params = subject.validRequestParameters(parsed, null);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    it("ensures that all of the necessary parameters have been provided", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"" +
          "}" +
          "}";
      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setType("certificate");
      DocumentContext parsed = jsonPath.parse(json);

      CertificateSecretParameters params = subject.validRequestParameters(parsed, null);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

      subject.validateJsonKeys(parsed);
      params = subject.validRequestParameters(parsed, null);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    describe("making CAs", () -> {
      it("is CA when isCA is true and defaults to self-signed when 'ca' params is not present" , () -> {
        String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"is_ca\": true" +
          "}" +
          "}";

        DocumentContext parsed = jsonPath.parse(json);
        CertificateSecretParameters params = subject.validRequestParameters(parsed, null);
        assertThat(params.getIsCA(), equalTo(true));
        assertThat(params.getSelfSign(), equalTo(true));
      });

      it("is CA when isCA is true and respects CA param (which will be used to sign this CA)", () -> {
        String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"is_ca\": true," +
          "\"ca\": \"My Ca\"" +
          "}" +
          "}";

        DocumentContext parsed = jsonPath.parse(json);
        CertificateSecretParameters params = subject.validRequestParameters(parsed, null);
        assertThat(params.getIsCA(), equalTo(true));
        assertThat(params.getSelfSign(), equalTo(false));
        assertThat(params.getCaName(), equalTo("My Ca"));
      });
    });

    describe("when all parameters are omitted", () -> {
      beforeEach(() -> {
        String json = "{" +
            "\"type\":\"certificate\"," +
            "\"parameters\":{" +
            "}" +
            "}";
        parsed = jsonPath.parse(json);
      });

      itThrowsWithMessage("for a certificate generation request", ParameterizedValidationException.class, "error.missing_certificate_parameters", () -> {
          subject.validRequestParameters(parsed, null);
      });

      itThrowsWithMessage("for a certificate authority generation request", ParameterizedValidationException.class, "error.missing_certificate_parameters", () -> {
          subject.validCertificateAuthorityParameters(parsed);
      });
    });

    describe("params that should be excluded for Certificate Authority are excluded", () -> {
      itThrows("only allowed parameters", ParameterizedValidationException.class, () -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"parameters\":{" +
            "\"organization\": \"Organization\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"alternative_names\": [\"my-alternative-name-1\", \"my-alternative-name-2\"]," +
            "\"ca\":\"my-ca\"," +
            "\"foo\": \"bar\"," +
            "}" +
            "}";
        parsed = jsonPath.parse(json);
        subject.validateJsonKeys(parsed);
      });
    });

    describe("validates the parameter holder at least once", () -> {
      beforeEach(() -> {
        mockParams = mock(CertificateSecretParameters.class);
        when(certificateSecretParametersFactory.get()).thenReturn(mockParams);
        parsed = jsonPath.parse("{}");
      });

      it("on a certificate generator request", () -> {
        subject.validRequestParameters(parsed, null);
        verify(mockParams, times(2)).validate();
      });

      it("on a certificate authority request", () -> {
        subject.validCertificateAuthorityParameters(parsed);
        verify(mockParams, times(1)).validate();
      });
    });

    it("ensures that key length is added", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"key_length\": 3072" +
          "}" +
          "}";

      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setType("certificate");
      expectedParameters.setKeyLength(3072);

      CertificateSecretParameters params = subject.validRequestParameters(jsonPath.parse(json), null);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    describe("populating an entity from JSON", () -> {
      final NamedCertificateSecret secret = new NamedCertificateSecret("abc");

      beforeEach(() -> {
        doReturn(new Certificate("my-root", "my-cert", "my-priv"))
            .when(certificateGenerator)
            .generateSecret(any(CertificateSecretParameters.class));
      });

      it("can populate an entity from JSON", () -> {
        String requestJson = "{\"type\":\"certificate\",\"parameters\":{\"common_name\":\"abc.com\",\"ca\":\"my-ca-name\"}}";
        parsed = jsonPath.parse(requestJson);
        subject.populateEntityFromJson(secret, parsed);

        verify(certificateGenerator).generateSecret(isA(CertificateSecretParameters.class));

        assertThat(secret.getCa(), equalTo("my-root"));
        assertThat(secret.getCertificate(), equalTo("my-cert"));
        assertThat(secret.getCaName(), equalTo("my-ca-name"));
      });
    });

    describe("regenerating certificates", () -> {
      beforeEach(() -> {
        Security.addProvider(new BouncyCastleProvider());
      });

      it("can creates correct parameters from entity from the entity", () -> {
        NamedCertificateSecret certificateSecret = new NamedCertificateSecret("my-cert")
            .setCertificate(TEST_CERT)
            .setCaName("my-ca");
        CertificateSecretParameters expectedParameters = new CertificateSecretParameters(certificateSecret.getCertificate());
        CertificateSecretParameters actualParameters = subject.validRequestParameters(jsonPath.parse("{\"regenerate\":true}"), certificateSecret);
        assertThat(actualParameters, samePropertyValuesAs(expectedParameters));
      });

      itThrowsWithMessage("regeneration is not allowed if caName is not present", ParameterizedValidationException.class, "error.cannot_regenerate_non_generated_credentials", () -> {
        NamedCertificateSecret entity = new NamedCertificateSecret("foo");
        subject.validRequestParameters(jsonPath.parse("{\"regenerate\":true}"), entity);
      });
    });
  }
}
