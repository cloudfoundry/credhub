package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import com.jayway.jsonpath.internal.JsonContext;
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

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doReturn;
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

  String requestJson = "{" +
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

  private DocumentContext parsedRequest;
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
        subject.namedCertificateAuthorityDataService = namedCertificateAuthorityDataService;
        parsedRequest = jsonPath.parse(requestJson);
      });

      it("validates the json keys", () -> {
        subject.validateJsonKeys(parsedRequest);
        // no exception
      });
    });

    describe("#populateEntityFromJson", () -> {
      it("updates the entity with the encrypted private key for a new CA", () -> {
        doReturn(new CertificateAuthority("root", "fake-certificate", "fake-private-key")).when(certificateGenerator).generateCertificateAuthority(any());
        NamedCertificateAuthority namedCertificateAuthority = new NamedCertificateAuthority("my-fake-ca");
        DocumentContext documentContext = new JsonContext().parse(requestJson);

        subject.populateEntityFromJson(namedCertificateAuthority, documentContext);

        verify(namedCertificateAuthorityDataService).updatePrivateKey(namedCertificateAuthority, "fake-private-key");
      });
    });

    describe("when random parameters are provided", () -> {
      itThrows("it rejects request", ParameterizedValidationException.class, () -> {
        String json = "{" +
            "\"type\":\"root\"," +
            "\"foo\":\"bar\"" +
            "}";

        parsedRequest = jsonPath.parse(json);
        subject.validateJsonKeys(parsedRequest);
      });
    });
  }
}
