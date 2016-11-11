package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.data.NamedCertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CertificateGeneratorRequestTranslatorTest {

  @Autowired
  ParseContext jsonPath;

  @Autowired
  @InjectMocks
  @Spy
  BCCertificateGenerator secretGenerator;

  @Mock
  CertificateSecretParameters certificateSecretParameters;

  @Mock
  CertificateSecretParametersFactory certificateSecretParametersFactory;

  @InjectMocks
  CertificateGeneratorRequestTranslator subject;

  @Spy
  @Autowired
  NamedCertificateAuthorityDataService certificateAuthorityDataService;

  private DocumentContext parsed;
  private CertificateSecretParameters mockParams;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());
      when(certificateSecretParametersFactory.get()).thenCallRealMethod();
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
          "\"alternative_names\": [\"my-alternative-name-1\", \"my-alternative-name-2\"]," +
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
      expectedParameters.addAlternativeNames("my-alternative-name-1", "my-alternative-name-2");
      expectedParameters.setCaName("My Ca");
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
          subject.validRequestParameters(parsed, null);
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
          "\"alternative_names\": [\"foo\", \"bar\"]" +
          "}" +
          "}";

      CertificateSecretParameters expectedParameters = new CertificateSecretParameters();
      expectedParameters.setOrganization("organization.io");
      expectedParameters.setState("My State");
      expectedParameters.setCountry("My Country");
      expectedParameters.setType("certificate");
      expectedParameters.addAlternativeNames("foo", "bar");

      DocumentContext parsed = jsonPath.parse(json);
      subject.validateJsonKeys(parsed);
      CertificateSecretParameters params = subject.validRequestParameters(jsonPath.parse(json), null);
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

      CertificateSecretParameters params = subject.validRequestParameters(parsed, null);
      assertThat(params, BeanMatchers.theSameAs(expectedParameters));

      subject.validateJsonKeys(parsed);
      params = subject.validRequestParameters(parsed, null);
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
        doReturn(new CertificateSecret(null, null, "my-root", "my-cert", "my-priv"))
            .when(secretGenerator)
            .generateSecret(any(CertificateSecretParameters.class));
      });

      it("can populate an entity from JSON", () -> {
        String requestJson = "{\"type\":\"certificate\",\"parameters\":{\"common_name\":\"abc.com\",\"ca\":\"my-ca-name\"}}";
        parsed = jsonPath.parse(requestJson);
        subject.populateEntityFromJson(secret, parsed);

        verify(secretGenerator).generateSecret(isA(CertificateSecretParameters.class));

        assertThat(secret.getCa(), equalTo("my-root"));
        assertThat(secret.getCertificate(), equalTo("my-cert"));
        assertThat(secret.getPrivateKey(), equalTo("my-priv"));
        assertThat(secret.getCaName(), equalTo("my-ca-name"));
      });
    });

    it("can regenerate using the existing entity and json", () -> {
      NamedCertificateAuthority certificateAuthority = setupCa();

      CertificateSecretParameters parameters = new CertificateSecretParameters();
      parameters.setCaName("my-root");
      parameters.setCommonName("Credhub Unit Tests");
      parameters.setKeyLength(1024);
      parameters.setDurationDays(30);
      parameters.addAlternativeNames("another-name");
      CertificateSecret secret = secretGenerator.generateSecret(parameters);

      String originalPrivateKey = secret.getCertificateBody().getPrivateKey();
      String originalCertificate = secret.getCertificateBody().getCertificate();

      NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret();
      namedCertificateSecret.setCaName("my-root");
      namedCertificateSecret.setCa(secret.getCertificateBody().getCa());
      namedCertificateSecret.setCertificate(originalCertificate);
      namedCertificateSecret.setPrivateKey(originalPrivateKey);

      subject.populateEntityFromJson(namedCertificateSecret, jsonPath.parse("{\"regenerate\":true}"));

      assertThat(namedCertificateSecret.getCertificate(), not(equalTo(originalCertificate)));
      assertNotNull(namedCertificateSecret.getCertificate());
      assertThat(namedCertificateSecret.getPrivateKey(), not(equalTo(originalPrivateKey)));
      assertNotNull(namedCertificateSecret.getPrivateKey());

      assertThat(namedCertificateSecret.getCaName(), equalTo("my-root"));
      assertThat(namedCertificateSecret.getCa(), equalTo(certificateAuthority.getCertificate()));

      assertThat(namedCertificateSecret.getKeyLength(), equalTo(1024));
      assertThat(namedCertificateSecret.getDurationDays(), equalTo(30));

      ASN1Sequence sequence = (ASN1Sequence) namedCertificateSecret.getAlternativeNames().getParsedValue();
      assertThat(((DERTaggedObject) sequence.getObjectAt(0)).getEncoded(), equalTo(new GeneralName(GeneralName.dNSName, "another-name").getEncoded()));
    });

    it("can regenerate using the existing entity and json when there are no alternative names", () -> {
      setupCa();

      CertificateSecretParameters parameters = new CertificateSecretParameters();
      parameters.setCaName("my-root");
      parameters.setCommonName("Credhub Unit Tests");
      CertificateSecret secret = secretGenerator.generateSecret(parameters);

      String originalPrivateKey = secret.getCertificateBody().getPrivateKey();
      String originalCertificate = secret.getCertificateBody().getCertificate();

      NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret();
      namedCertificateSecret.setCaName("my-root");
      namedCertificateSecret.setCa(secret.getCertificateBody().getCa());
      namedCertificateSecret.setCertificate(originalCertificate);
      namedCertificateSecret.setPrivateKey(originalPrivateKey);

      subject.populateEntityFromJson(namedCertificateSecret, jsonPath.parse("{\"regenerate\":true}"));

      assertNull(namedCertificateSecret.getAlternativeNames());
    });


    itThrowsWithMessage("regeneration is not allowed if caName is not present", ParameterizedValidationException.class, "error.cannot_regenerate_non_generated_credentials", () -> {
      subject.validRequestParameters(jsonPath.parse("{\"regenerate\":true}"), new NamedCertificateSecret("foo", "", "", ""));
    });
  }

  private NamedCertificateAuthority setupCa() throws Exception {
    CertificateSecretParameters authorityParameters = new CertificateSecretParameters();
    authorityParameters.setCommonName("my-root");
    CertificateAuthority certificateSecret = secretGenerator.generateCertificateAuthority(authorityParameters);
    NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority("my-root");
    certificateAuthority.setCertificate(certificateSecret.getCertificateAuthorityBody().getCertificate())
        .setPrivateKey(certificateSecret.getCertificateAuthorityBody().getPrivateKey());

    when(certificateAuthorityDataService.findMostRecentByNameWithDecryption("my-root")).thenReturn(certificateAuthority);

    return certificateAuthority;
  }
}
