package io.pivotal.security.mapper;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.ParseContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.controller.v1.CertificateSecretParametersFactory;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.generator.BCCertificateAuthorityGenerator;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.secret.CertificateAuthority;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.generator.BCCertificateGenerator;
import io.pivotal.security.service.EncryptionKeyService;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;

import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.describedAs;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
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

  @Autowired
  ParseContext jsonPath;

  @SpyBean
  BCCertificateGenerator certificateGenerator;

  @SpyBean
  BCCertificateAuthorityGenerator certificateAuthorityGenerator;

  @MockBean
  CertificateSecretParametersFactory certificateSecretParametersFactory;

  @Autowired
  CertificateGeneratorRequestTranslator subject;

  @SpyBean
  CertificateAuthorityDataService certificateAuthorityDataService;

  @Autowired
  EncryptionKeyService encryptionKeyService;

  private DocumentContext parsed;
  private CertificateSecretParameters mockParams;

  {
    wireAndUnwire(this, false);

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

    it("ensures that key length is set to default", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"parameters\":{" +
          "\"organization\": \"organization.io\"" +
          "}" +
          "}";

      DocumentContext parsed = jsonPath.parse(json);
      CertificateSecretParameters params = subject.validRequestParameters(parsed, null);
      assertThat(params.getKeyLength(), equalTo(2048));
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
      parameters.addExtendedKeyUsage("code_signing");
      parameters.addKeyUsage("digital_signature", "non_repudiation");
      Certificate secret = certificateGenerator.generateSecret(parameters);

      String originalPrivateKey = secret.getPrivateKey();
      String originalCertificate = secret.getCertificate();

      NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret();
      namedCertificateSecret.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
      namedCertificateSecret.setCaName("my-root");
      namedCertificateSecret.setCa(secret.getCaCertificate());
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

      ASN1Sequence alternativeNameSequence = (ASN1Sequence) namedCertificateSecret.getAlternativeNames().getParsedValue();
      assertThat(((DERTaggedObject) alternativeNameSequence.getObjectAt(0)).getEncoded(), equalTo(new GeneralName(GeneralName.dNSName, "another-name").getEncoded()));

      assertThat(namedCertificateSecret.getExtendedKeyUsage().hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning), equalTo(true));
      assertThat(namedCertificateSecret.getExtendedKeyUsage().hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth), equalTo(false));

      assertThat(namedCertificateSecret.getKeyUsage().hasUsages(KeyUsage.digitalSignature | KeyUsage.nonRepudiation), equalTo(true));
    });

    it("can regenerate using the existing entity and json when there are no alternative names", () -> {
      setupCa();

      CertificateSecretParameters parameters = new CertificateSecretParameters();
      parameters.setCaName("my-root");
      parameters.setCommonName("Credhub Unit Tests");
      Certificate secret = certificateGenerator.generateSecret(parameters);

      String originalPrivateKey = secret.getPrivateKey();
      String originalCertificate = secret.getCertificate();

      NamedCertificateSecret namedCertificateSecret = new NamedCertificateSecret();
      namedCertificateSecret.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
      namedCertificateSecret.setCaName("my-root");
      namedCertificateSecret.setCa(secret.getCaCertificate());
      namedCertificateSecret.setCertificate(originalCertificate);
      namedCertificateSecret.setPrivateKey(originalPrivateKey);

      subject.populateEntityFromJson(namedCertificateSecret, jsonPath.parse("{\"regenerate\":true}"));

      assertNull(namedCertificateSecret.getAlternativeNames());
    });


    itThrowsWithMessage("regeneration is not allowed if caName is not present", ParameterizedValidationException.class, "error.cannot_regenerate_non_generated_credentials", () -> {
      NamedCertificateSecret entity = new NamedCertificateSecret("foo");
      subject.validRequestParameters(jsonPath.parse("{\"regenerate\":true}"), entity);
    });
  }

  private NamedCertificateAuthority setupCa() throws Exception {
    CertificateSecretParameters authorityParameters = new CertificateSecretParameters();
    authorityParameters.setCommonName("my-root");
    CertificateAuthority certificateSecret = certificateAuthorityGenerator.generateSecret(authorityParameters);
    NamedCertificateAuthority certificateAuthority = new NamedCertificateAuthority("my-root");
    certificateAuthority.setEncryptionKeyUuid(encryptionKeyService.getActiveEncryptionKeyUuid());
    certificateAuthority.setCertificate(certificateSecret.getCertificate())
        .setPrivateKey(certificateSecret.getPrivateKey());

    when(certificateAuthorityDataService.findMostRecent("my-root")).thenReturn(certificateAuthority);

    return certificateAuthority;
  }
}
