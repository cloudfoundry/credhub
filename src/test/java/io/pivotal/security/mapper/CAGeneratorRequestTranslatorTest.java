package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.view.CertificateAuthority;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.refEq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import io.pivotal.security.view.ParameterizedValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@ActiveProfiles("unit-test")
public class CAGeneratorRequestTranslatorTest {

  @Autowired
  private Configuration jsonConfiguration;

  @InjectMocks
  @Autowired
  CAGeneratorRequestTranslator subject;

  @Mock
  BCCertificateGenerator certificateGenerator;

  @Autowired
  CertificateSecretParametersFactory parametersFactory;

  @InjectMocks
  @Spy
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  private DocumentContext parsed;
  private CertificateSecretParameters fullParams = new CertificateSecretParameters()
      .setCommonName("My Common Name")
      .setOrganization("Organization")
      .setOrganizationUnit("My Unit")
      .setLocality("My Locality")
      .setState("My State")
      .setCountry("My Country")
      .setKeyLength(2048)
      .setDurationDays(365)
      .setType("root");

  {
    wireAndUnwire(this);

    describe("when all parameters are provided", () -> {
      beforeEach(() -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"parameters\":{" +
            "\"common_name\":\"My Common Name\", " +
            "\"organization\": \"Organization\"," +
            "\"organization_unit\": \"My Unit\"," +
            "\"locality\": \"My Locality\"," +
            "\"state\": \"My State\"," +
            "\"country\": \"My Country\"," +
            "\"key_length\": 2048," +
            "\"duration\": 365" +
            "}" +
            "}";
        parsed = JsonPath.using(jsonConfiguration).parse(json);
      });

      it("validates the json keys", () -> {
        subject.validateJsonKeys(parsed);
        // no exception
      });

      it("creates view with specified parameters", () -> {
        when(certificateGenerator.generateCertificateAuthority(refEq(fullParams)))
            .thenReturn(new CertificateAuthority("root", "theCert", "thePrivateKey"));

        CertificateAuthority certificateAuthority = subject.createAuthorityFromJson(parsed);

        assertThat(certificateAuthority.getType(), equalTo("root"));
        assertThat(certificateAuthority.getCertificateAuthorityBody().getCertificate(), equalTo("theCert"));
        assertThat(certificateAuthority.getCertificateAuthorityBody().getPrivateKey(), equalTo("thePrivateKey"));
      });

      it("validates parameters", () -> {
        subject.createAuthorityFromJson(parsed);

        Mockito.verify(certificateGeneratorRequestTranslator, times(1)).validCertificateAuthorityParameters(parsed);
      });

      itThrows("returns error when type is not 'root'", ParameterizedValidationException.class, () -> {
        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse("{\"type\":\"notRoot\"}");
        subject.createAuthorityFromJson(parsed);
      });

      itThrows("returns error when type is not provided", ParameterizedValidationException.class, () -> {
        DocumentContext parsed = JsonPath.using(jsonConfiguration).parse("{}");
        subject.createAuthorityFromJson(parsed);
      });
    });

    describe("when random parameters are provided", () -> {
      itThrows("it rejects request", ParameterizedValidationException.class, () -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"foo\":\"bar\"" +
            "}";

        parsed = JsonPath.using(jsonConfiguration).parse(json);
        subject.validateJsonKeys(parsed);
      });
    });
  }
}
