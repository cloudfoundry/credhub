package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import javax.validation.ValidationException;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class CertificateGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  private CertificateGeneratorRequestTranslator subject;
  private DocumentContext parsed;
  private CertificateSecretParameters mockParams;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      subject = new CertificateGeneratorRequestTranslator();
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
          "\"duration\": 1000" +
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
      DocumentContext parsed = JsonPath.using(configuration).parse(json);

      CertificateSecretParameters params = subject.validCertificateGeneratorRequest(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

      params = subject.validRequestParameters(parsed);
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

      CertificateSecretParameters params = subject.validCertificateGeneratorRequest(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

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
          subject.validCertificateGeneratorRequest(parsed);
          fail();
        } catch (ValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
        }
      });

      it("fails on a certificate authority request", () -> {
        try {
          subject.validRequestParameters(parsed);
          fail();
        } catch (ValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
        }
      });
    });

    describe("validates the parameter holder at least once", () -> {

      beforeEach(() -> {
        mockParams = mock(CertificateSecretParameters.class);
        subject.setParametersSupplier(() -> mockParams);
        parsed = JsonPath.using(configuration).parse("{}");
      });

      it("on a certificate generator request", () -> {
        subject.validCertificateGeneratorRequest(parsed);
        verify(mockParams, times(2)).validate();
      });

      it("on a certificate authority request", () -> {
        subject.validRequestParameters(parsed);
        verify(mockParams, times(1)).validate();
      });
    });

    it("ensures that alternative names are added as necessary", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"alternative_name\": [\"foo\", \"boo pivotal.io\"]" +
          "}" +
          "}";

      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setType("certificate");
      expectedParameters.addAlternativeName("foo");
      expectedParameters.addAlternativeName("boo pivotal.io");

      CertificateSecretParameters params = subject.validCertificateGeneratorRequest(JsonPath.using(configuration).parse(json));
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

      CertificateSecretParameters params = subject.validCertificateGeneratorRequest(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

      params = subject.validRequestParameters(parsed);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));
    });

    describe("params that should be excluded for Certificate Authority are excluded", () -> {
      it("creates parameter holder with only allowed parameters", () -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"parameters\":{" +
            "\"organization\": \"Organization\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"alternative_name\": [\"My Alternative Name 1\", \"My Alternative Name 2\"]," +
            "\"ca\":\"my-ca\"," +
            "\"foo\": \"bar\"," +
            "}" +
            "}";
        parsed = JsonPath.using(configuration).parse(json);
        CertificateSecretParameters expectedParams = new CertificateSecretParameters()
            .setOrganization("Organization")
            .setState("My State")
            .setCountry("My Country")
            .setKeyLength(2048) // provided by default
            .setDurationDays(365)
            .setType("root");

        CertificateSecretParameters parameters = subject.validRequestParameters(parsed);
        assertThat(parameters, BeanMatchers.theSameAs(expectedParams));
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
  }
}