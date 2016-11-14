package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.data.NamedCertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.ParameterizedValidationException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.refEq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CAGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @InjectMocks
  @Autowired
  CAGeneratorRequestTranslator subject;

  @Mock
  BCCertificateGenerator certificateGenerator;

  @Mock
  NamedCertificateAuthorityDataService namedCertificateAuthorityDataService;

  @Autowired
  CertificateSecretParametersFactory parametersFactory;

  @InjectMocks
  @Spy
  CertificateGeneratorRequestTranslator certificateGeneratorRequestTranslator;

  private NamedCertificateAuthority certificateAuthority;

  private final String requestJson = "{" +
      "\"type\":\"root\"," +
      "\"name\":\"sailor-moon\"," +
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

  private final CertificateSecretParameters fullParams = new CertificateSecretParameters()
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
      it("validates the json keys", () -> {
        subject.validateJsonKeys(jsonPath.parse(requestJson));
        // no exception
      });
    });

    describe("when random parameters are provided", () -> {
      itThrows("it rejects request", ParameterizedValidationException.class, () -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"foo\":\"bar\"" +
            "}";
        subject.validateJsonKeys(jsonPath.parse(json));
      });
    });

    describe("#populateEntityFromJson", () -> {
      beforeEach(() -> {
        doReturn(
            new CertificateAuthority("root", "fake-certificate", "fake-private-key")
        ).when(certificateGenerator).generateCertificateAuthority(refEq(fullParams));
        certificateAuthority = new NamedCertificateAuthority("fake-ca");
        subject.populateEntityFromJson(certificateAuthority, jsonPath.parse(requestJson));
      });

      it("validates parameters", () -> {
        verify(certificateGeneratorRequestTranslator, times(1))
            .validCertificateAuthorityParameters(eq(jsonPath.parse(requestJson)));
      });

      it("generates new certificate authority as view", () -> {
        verify(certificateGenerator, times(1)).generateCertificateAuthority(refEq(fullParams));
      });

      it("sets appropriate fields on the entity", () -> {
        assertThat(certificateAuthority.getType(), equalTo("root"));
        assertThat(certificateAuthority.getCertificate(), equalTo("fake-certificate"));
        assertThat(certificateAuthority.getPrivateKey(), equalTo("fake-private-key"));
      });

      itThrowsWithMessage("when type is not root", ParameterizedValidationException.class, "error.bad_authority_type", () -> {
        subject.populateEntityFromJson(new NamedCertificateAuthority("fake-ca"), jsonPath.parse("{\"type\":\"notRoot\"}"));
      });

      itThrowsWithMessage("when type is not provided", ParameterizedValidationException.class, "error.bad_authority_type", () -> {
        subject.populateEntityFromJson(new NamedCertificateAuthority("fake-ca"), jsonPath.parse("{}"));
      });
    });
  }
}
