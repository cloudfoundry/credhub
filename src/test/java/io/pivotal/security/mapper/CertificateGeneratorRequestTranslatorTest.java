package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.*;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CertificateGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @Mock
  SecretGenerator secretGenerator;

  @Mock
  CertificateSecretParameters certificateSecretParameters;

  @Mock
  CertificateSecretParametersFactory certificateSecretParametersFactory;

  @InjectMocks
  private CertificateGeneratorRequestTranslator subject;

  private DocumentContext parsed;
  private CertificateSecretParameters mockParams;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(certificateSecretParametersFactory.get()).thenCallRealMethod();
    });

    it("ensures that all of the allowable parameters have been provided", () -> {
      String json = "{" +
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
          "\"alternative_names\": [\"My Alternative Name 1\", \"My Alternative Name 2\"]," +
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
      expectedParameters.addAlternativeName("My Alternative Name 1");
      expectedParameters.addAlternativeName("My Alternative Name 2");
      DocumentContext parsed = jsonPath.parse(json);

      subject.validateJsonKeys(parsed);
      CertificateSecretParameters params = subject.validRequestParameters(parsed);
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

      CertificateSecretParameters params = subject.validRequestParameters(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

      subject.validateJsonKeys(parsed);
      params = subject.validRequestParameters(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
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

      it("fails on a certificate generator request", () -> {
        try {
          subject.validRequestParameters(parsed);
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
        }
      });

      it("fails on a certificate authority request", () -> {
        try {
          subject.validCertificateAuthorityParameters(parsed);
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
        }
      });
    });

    it("ensures that alternative names are added as necessary", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"alternative_names\": [\"foo\", \"boo pivotal.io\"]" +
          "}" +
          "}";

      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setType("certificate");
      expectedParameters.addAlternativeName("foo");
      expectedParameters.addAlternativeName("boo pivotal.io");

      subject.validateJsonKeys(parsed);
      CertificateSecretParameters params = subject.validRequestParameters(jsonPath.parse(json));
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    it("ensures that key length is set to default", () -> {
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
      expectedParameters.setKeyLength(2048);
      DocumentContext parsed = jsonPath.parse(json);

      CertificateSecretParameters params = subject.validRequestParameters(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

      subject.validateJsonKeys(parsed);
      params = subject.validRequestParameters(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    describe("params that should be excluded for Certificate Authority are excluded", () -> {
      itThrows("only allowed parameters", ParameterizedValidationException.class, () -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"parameters\":{" +
            "\"organization\": \"Organization\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"alternative_names\": [\"My Alternative Name 1\", \"My Alternative Name 2\"]," +
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
        subject.validRequestParameters(parsed);
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

      CertificateSecretParameters params = subject.validRequestParameters(jsonPath.parse(json));
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    it("can populate an entity from JSON", () -> {
      when(secretGenerator.generateSecret(any(RequestParameters.class)))
          .thenReturn(new CertificateSecret(null, null, "my-root", "my-cert", "my-priv"));

      final NamedCertificateSecret secret = new NamedCertificateSecret("abc");
      String requestJson = "{\"type\":\"certificate\",\"parameters\":{\"common_name\":\"abc.com\"}}";
      parsed = jsonPath.parse(requestJson);
      subject.populateEntityFromJson(secret, parsed);

      verify(secretGenerator).generateSecret(isA(CertificateSecretParameters.class));

      assertThat(secret.getCa(), equalTo("my-root"));
      assertThat(secret.getCertificate(), equalTo("my-cert"));
      assertThat(secret.getPrivateKey(), equalTo("my-priv"));
    });
  }
}
