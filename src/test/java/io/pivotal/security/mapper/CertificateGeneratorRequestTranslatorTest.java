package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.SecretGenerator;
import io.pivotal.security.view.CertificateSecret;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.pivotal.security.view.ParameterizedValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class CertificateGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  @Mock
  SecretGenerator secretGenerator;

  @InjectMocks
  private CertificateGeneratorRequestTranslator subject;

  private DocumentContext parsed;
  private CertificateSecretParameters mockParams;

  {
    wireAndUnwire(this);

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
      DocumentContext parsed = JsonPath.using(configuration).parse(json);

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
      DocumentContext parsed = JsonPath.using(configuration).parse(json);

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
        parsed = JsonPath.using(configuration).parse(json);
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
      CertificateSecretParameters params = subject.validRequestParameters(JsonPath.using(configuration).parse(json));
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
      DocumentContext parsed = JsonPath.using(configuration).parse(json);

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
        parsed = JsonPath.using(configuration).parse(json);
        subject.validateJsonKeys(parsed);
      });
    });

    describe("validates the parameter holder at least once", () -> {

      beforeEach(() -> {
        mockParams = mock(CertificateSecretParameters.class);
        subject.setParametersSupplier(() -> mockParams);
        parsed = JsonPath.using(configuration).parse("{}");
      });

      afterEach(() -> {
        subject.setParametersSupplier(() -> new CertificateSecretParameters());
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

      CertificateSecretParameters params = subject.validRequestParameters(JsonPath.using(configuration).parse(json));
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    it("can populate an entity from JSON", () -> {
      when(secretGenerator.generateSecret(any(RequestParameters.class)))
          .thenReturn(new CertificateSecret(null, null, "my-root", "my-cert", "my-priv"));

      final NamedCertificateSecret secret = new NamedCertificateSecret("abc");
      String requestJson = "{\"type\":\"certificate\",\"parameters\":{\"common_name\":\"abc.com\"}}";
      parsed = JsonPath.using(configuration).parse(requestJson);
      subject.populateEntityFromJson(secret, parsed);
      assertThat(secret.getCa(), notNullValue());
      assertThat(secret.getCertificate(), notNullValue());
      assertThat(secret.getPrivateKey(), notNullValue());
    });
  }
}