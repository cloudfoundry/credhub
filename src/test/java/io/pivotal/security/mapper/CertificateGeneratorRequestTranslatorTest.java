package io.pivotal.security.mapper;

import com.greghaskins.spectrum.SpringSpectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.CertificateSecretParameters;
import io.pivotal.security.model.GeneratorRequest;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import javax.validation.ValidationException;

import static com.greghaskins.spectrum.SpringSpectrum.beforeEach;
import static com.greghaskins.spectrum.SpringSpectrum.it;
import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@RunWith(SpringSpectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class CertificateGeneratorRequestTranslatorTest {

  @Autowired
  Configuration configuration;

  private CertificateGeneratorRequestTranslator subject;

  {
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
          "\"country\": \"My Country\"" +
          "}" +
          "}";
      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setCommonName("My Common Name");
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setOrganizationUnit("My Unit");
      expectedParameters.setLocality("My Locality");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");

      GeneratorRequest<CertificateSecretParameters> cgRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
      assertThat(cgRequest.getParameters(), reflectiveEqualTo(expectedParameters));
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

      GeneratorRequest<CertificateSecretParameters> cgRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
      assertThat(cgRequest.getParameters(), reflectiveEqualTo(expectedParameters));
    });

    it("ensures failure when organization is omitted", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"" +
          "}" +
          "}";

      try {
        subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
        fail();
      }
      catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
      }
    });

    it("ensures failure when state is omitted", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"country\": \"My Country\"" +
          "}" +
          "}";
      try {
        subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
        fail();
      }
      catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
      }
    });

    it("ensures failure when country is omitted", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "}" +
          "}";
      try {
        subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
        fail();
      }
      catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.missing_certificate_parameters"));
      }
    });

    it("ensures that alternative names are added as necessary", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"alternate_name\": [\"foo\", \"boo pivotal.io\"]" +
          "}" +
          "}";

      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.addAlternateName("foo");
      expectedParameters.addAlternateName("boo pivotal.io");

      GeneratorRequest<CertificateSecretParameters> cgRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));

      assertThat(cgRequest.getParameters(), reflectiveEqualTo(expectedParameters));
    });

    it("ensures that key length is added", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"," +
          "\"state\": \"My State\"," +
          "\"country\": \"My Country\"," +
          "\"key_length\": 1024" +
          "}" +
          "}";

      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setKeyLength(1024);

      GeneratorRequest<CertificateSecretParameters> cgRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));

      assertThat(cgRequest.getParameters(), reflectiveEqualTo(expectedParameters));
    });
  }
}