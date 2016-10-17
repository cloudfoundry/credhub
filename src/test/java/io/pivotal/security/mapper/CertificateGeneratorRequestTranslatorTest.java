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
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.exparity.hamcrest.BeanMatchers;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.security.Security;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class CertificateGeneratorRequestTranslatorTest {

  // Issuer: O=Pivotal, ST=CA, C=US, CN=Credhub Unit Tests CA, OU=CredHub, L=San Francisco
  // Subject: O=Pivotal, ST=CA, C=US, CN=Credhub Unit Tests, OU=CredHub, L=San Francisco
  private static final String TEST_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
      "MIIDhzCCAm+gAwIBAgIUabl2OG9xnWMbdwsMglP1ynLXZdMwDQYJKoZIhvcNAQEL\n" +
      "BQAwdjEQMA4GA1UECgwHUGl2b3RhbDELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVT\n" +
      "MR4wHAYDVQQDDBVDcmVkaHViIFVuaXQgVGVzdHMgQ0ExEDAOBgNVBAsMB0NyZWRI\n" +
      "dWIxFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28wHhcNMTYxMDE0MTczMzQzWhcNMTcx\n" +
      "MDE0MTczMzQzWjBzMRAwDgYDVQQKDAdQaXZvdGFsMQswCQYDVQQIDAJDQTELMAkG\n" +
      "A1UEBhMCVVMxGzAZBgNVBAMMEkNyZWRodWIgVW5pdCBUZXN0czEQMA4GA1UECwwH\n" +
      "Q3JlZEh1YjEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzCCASIwDQYJKoZIhvcNAQEB\n" +
      "BQADggEPADCCAQoCggEBALEfEeqPmzqSWm+DfdlrYB2JwFeVqCcbo2L2sYTY+ue9\n" +
      "nFwRoD/QEy2ocFJxYoRZA3po0+FiQ7yMK0Lp1f7AUAInWY3VuFp425AyaDFS1oxR\n" +
      "nTRcZcgu06AQxJdy5KhWf9oxwedL6tnBvt20VJp6zQvIMrkFO4KfbSZ0keR0ulDg\n" +
      "QUraEwI0lzFZ8LfD6FigILqnCr48+B0om79jprLzVw83GtjCyiIqUEf2sllpGn90\n" +
      "0WFOHLjXQ2Qdaka0tRDpDFQT+X7yvEVYdN8SBqpIa423ykw0Y/4xWwN5bmyz6pTL\n" +
      "uKvXWwhO8CqeoG9ineUiEMqV307jTyEZaPwNCE1gTfMCAwEAAaMQMA4wDAYDVR0T\n" +
      "AQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAaodDBvwJDvyLUH4VsN0ZY/hNUHmj\n" +
      "WDJYVVcjsd/dTkNMSGxIaHPmm6sjOlTHxVLdC8uc9RzTbGpyigMmKeT/lo1yH+Es\n" +
      "E7CPHzJgJWiU0y+MggBv8woRAfByTRlnHnW0wMFPSnFpRkfX012c2gAeqKE+/cxS\n" +
      "IVGym4gO5fMju5tIsbe6FIVvMsxQzNDy/nl9a905+vqSS8ZHra+lkfc+JTyC4fXP\n" +
      "ImCB8ZYcdM+nCmudHFkIB9MptX4MIl8ttRPz0rErmPrA6MbH/oSCte5XKE9+H+Jc\n" +
      "QZmvNrWHgZnngW/Ko07KXNUNC7iaT7Kudltmdyu6K8AA38z8Ys0claJ1FQ==\n" +
      "-----END CERTIFICATE-----";

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
      Security.addProvider(new BouncyCastleProvider());
      when(certificateSecretParametersFactory.get()).thenCallRealMethod();
    });

    it("ensures that all of the allowable parameters have been provided", () -> {
      String json = "{" +
          "\"type\":\"certificate\"," +
          "\"regenerate\":false," +
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
        when(secretGenerator.generateSecret(any(RequestParameters.class)))
            .thenReturn(new CertificateSecret(null, null, "my-root", "my-cert", "my-priv"));
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
      NamedCertificateSecret secret = new NamedCertificateSecret("test").setCertificate(TEST_CERTIFICATE).setCaName("my-ca-name");

      ArgumentCaptor<Object> parameterCaptor = ArgumentCaptor.forClass(Object.class);
      when(secretGenerator.generateSecret(parameterCaptor.capture()))
          .thenReturn(new CertificateSecret(null, null, "my-root", "my-cert", "my-priv"));

      subject.populateEntityFromJson(secret, jsonPath.parse("{\"regenerate\":true}"));

      CertificateSecretParameters requestParameters = (CertificateSecretParameters) parameterCaptor.getValue();
      assertNotNull(requestParameters.getX500Name());
      assertNotNull(requestParameters.getCa());
      assertThat(requestParameters.getX500Name().getRDNs(BCStyle.CN)[0].getFirst().getValue().toString(), equalTo("Credhub Unit Tests"));
      assertThat(secret.getCa(), equalTo("my-root"));
      assertThat(secret.getCertificate(), equalTo("my-cert"));
      assertThat(secret.getPrivateKey(), equalTo("my-priv"));
    });
  }
}
