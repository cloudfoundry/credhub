package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import com.greghaskins.spectrum.SpringSpectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.data.auditing.DateTimeProvider;

import static com.greghaskins.spectrum.SpringSpectrum.beforeAll;
import static com.greghaskins.spectrum.SpringSpectrum.beforeEach;
import static com.greghaskins.spectrum.SpringSpectrum.describe;
import static com.greghaskins.spectrum.SpringSpectrum.it;
import static com.greghaskins.spectrum.SpringSpectrum.itThrows;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.validation.ValidationException;

@RunWith(SpringSpectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class SignedCertificateGeneratorTest {

  final Instant now = Instant.now();
  final Calendar nowCalendar = Calendar.getInstance();

  DateTimeProvider timeProvider;
  RandomSerialNumberGenerator serialNumberGenerator;
  X509Certificate generatedCert;
  KeyPair issuerKeyPair;
  X500Principal caDn;
  KeyPair certKeyPair;
  PrivateKey issuerPrivateKey;
  CertificateSecretParameters inputParameters;

  @Autowired
  SignedCertificateGenerator subject;

  {
    beforeAll(() -> {
      Security.addProvider(new BouncyCastleProvider());
    });

    beforeEach(() -> {
      createAndInjectMocks();
      nowCalendar.setTime(Date.from(now));
      when(timeProvider.getNow()).thenReturn(nowCalendar);
      when(serialNumberGenerator.generate()).thenReturn(BigInteger.valueOf(12));
    });

    final SuiteBuilder validCertificateSuite = (makeCert) -> () -> {
      
      describe("with or without alternative names", () -> {

        beforeEach(makeCert::run);

        it("is not null", () -> {
          assertNotNull(generatedCert);
        });

        it("the signature is valid", () -> {
          generatedCert.verify(issuerKeyPair.getPublic());
        });

        it("has the correct metadata", () -> {
          assertThat(generatedCert.getIssuerX500Principal(), equalTo(caDn));
          assertThat(generatedCert.getSubjectX500Principal().getName(), equalTo("CN=my test cert,C=US,ST=CA," +
              "O=credhub"));
        });

        it("is valid for the appropriate time range", () -> {
          assertThat(generatedCert.getNotBefore(), equalTo(Date.from(now.truncatedTo(ChronoUnit.SECONDS))));
          assertThat(generatedCert.getNotAfter(), equalTo(Date.from(now.plus(Duration.ofDays(10)).truncatedTo
              (ChronoUnit.SECONDS))));
        });

        it("has a random serial number", () -> {
          verify(serialNumberGenerator).generate();
          assertThat(generatedCert.getSerialNumber(), equalTo(BigInteger.valueOf(12)));
        });

        it("contains the public key", () -> {
          assertThat(generatedCert.getPublicKey(), equalTo(certKeyPair.getPublic()));
        });

        it("has no alterative names", () -> {
          assertThat(generatedCert.getExtensionValue(Extension.subjectAlternativeName.getId()), nullValue());
        });
      });

      describe("with alternate names", () -> {

        beforeEach(() -> {
          inputParameters = new CertificateSecretParameters();
          inputParameters.setOrganization("my-org");
          inputParameters.setState("NY");
          inputParameters.setCountry("USA");
        });

        it("are supported", () -> {
          inputParameters.addAlternativeName("1.1.1.1");
          inputParameters.addAlternativeName("example.com");
          inputParameters.addAlternativeName("foo.pivotal.io");
          inputParameters.addAlternativeName("*.pivotal.io");

          makeCert.run();

          assertThat(generatedCert.getSubjectAlternativeNames(), containsInAnyOrder(
              contains(7, "1.1.1.1"),
              contains(2, "example.com"),
              contains(2, "foo.pivotal.io"),
              contains(2, "*.pivotal.io")
          ));
        });

        itThrows("with invalid special DNS characters throws a validation exception", ValidationException.class, () -> {
          inputParameters.addAlternativeName("foo!@#$%^&*()_-+=.com");
          makeCert.run();
        });

        itThrows("with space character throws a validation exception", ValidationException.class, () -> {
          inputParameters.addAlternativeName("foo pivotal.io");
          makeCert.run();
        });

        itThrows("with invalid IP address throws a validation exception", ValidationException.class, () -> {
          inputParameters.addAlternativeName("1.2.3.999");
          makeCert.run();
        });

        // email addresses are allowed in certificate spec, but we do not allow them per PM requirements
        itThrows("with email address throws a validation exception", ValidationException.class, () -> {
          inputParameters.addAlternativeName("x@y.com");
          makeCert.run();
        });

        itThrows("with URL throws a validation exception", ValidationException.class, () -> {
          inputParameters.addAlternativeName("https://foo.com");
          makeCert.run();
        });
      });
    };

    describe("a generated issuer-signed certificate", () -> {

      beforeEach(() -> {
        caDn = new X500Principal("O=foo\\,inc.,ST=\'my fav state\', C=\"adsf asdf\",OU=cool org, " +
            "EMAILADDRESS=x@y.com");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024); // doesn't matter for testing
        issuerKeyPair = generator.generateKeyPair();
        issuerPrivateKey = issuerKeyPair.getPrivate();

        certKeyPair = generator.generateKeyPair();
        inputParameters = new CertificateSecretParameters();
        inputParameters.setCommonName("my test cert");
        inputParameters.setCountry("US");
        inputParameters.setState("CA");
        inputParameters.setOrganization("credhub");
        inputParameters.setDurationDays(10);
      });

      final ThrowingRunnable makeCert = () -> {
        generatedCert = subject.getSignedByIssuer(caDn, issuerPrivateKey, certKeyPair,
            inputParameters);
      };

      describe("must behave like", validCertificateSuite.build(makeCert));

      it("is part of a trust chain with the ca", () -> {
        makeCert.run();
        final X509CertSelector target = new X509CertSelector();
        target.setCertificate(generatedCert);

        final TrustAnchor trustAnchor = new TrustAnchor(caDn, issuerKeyPair.getPublic(), null);
        final PKIXBuilderParameters builderParameters = new PKIXBuilderParameters(Collections.singleton
            (trustAnchor), target);

        final CertStore certStore = new JcaCertStoreBuilder()
            .addCertificate(new X509CertificateHolder(generatedCert.getEncoded()))
            .build();

        builderParameters.addCertStore(certStore);
        builderParameters.setRevocationEnabled(false);

        final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        final CertPathBuilderResult builderResult = certPathBuilder.build(builderParameters);
        builderResult.getCertPath();
      });
    });

    describe("a generated self-signed certificate", () -> {

      ThrowingRunnable makeCert = () -> {
        generatedCert = subject.getSelfSigned(certKeyPair, inputParameters);
      };

      beforeEach(() -> {
        caDn = new X500Principal("CN=my test cert,C=\"US\",ST=CA, O=credhub");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024); // doesn't matter for testing
        issuerKeyPair = generator.generateKeyPair();

        certKeyPair = issuerKeyPair;
        inputParameters = new CertificateSecretParameters();
        inputParameters.setCommonName("my test cert");
        inputParameters.setCountry("US");
        inputParameters.setState("CA");
        inputParameters.setOrganization("credhub");
        inputParameters.setDurationDays(10);
      });

      describe("must behave like", validCertificateSuite.build(makeCert));
    });
  }

  private void createAndInjectMocks() {
    // @Mock annotation doesn't seem to work, so do it manually
    timeProvider = Mockito.mock(DateTimeProvider.class);
    subject.timeProvider = timeProvider;
    serialNumberGenerator = Mockito.mock(RandomSerialNumberGenerator.class);
    subject.serialNumberGenerator = serialNumberGenerator;
  }

  interface ThrowingRunnable {
    void run() throws Exception;
  }

  interface SuiteBuilder {
    Spectrum.Block build(ThrowingRunnable makeCert);
  }
}