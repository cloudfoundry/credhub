package io.pivotal.security.mapper;

import com.greghaskins.spectrum.SpringSpectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.model.CertificateGeneratorRequest;
import io.pivotal.security.model.CertificateSecretParameters;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import static com.greghaskins.spectrum.SpringSpectrum.beforeEach;
import static com.greghaskins.spectrum.SpringSpectrum.it;
import static io.pivotal.security.matcher.ReflectiveEqualsMatcher.reflectiveEqualTo;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

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

    it("returns a CertificateGeneratorRequest for valid json", () -> {
      String json = "{\"type\":\"certificate\"}";
      CertificateGeneratorRequest generatorRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
      assertThat(generatorRequest.getType(), equalTo("certificate"));
    });

    it("ensures that all of the necessary parameters have been provided", () -> {
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

      CertificateGeneratorRequest cgRequest = subject.validGeneratorRequest(JsonPath.using(configuration).parse(json));
      assertThat(cgRequest.getParameters(), reflectiveEqualTo(expectedParameters));
    });
  }
}