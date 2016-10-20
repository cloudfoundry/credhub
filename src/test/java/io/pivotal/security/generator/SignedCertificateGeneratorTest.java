package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStoreBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.data.auditing.DateTimeProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
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

import static com.greghaskins.spectrum.Spectrum.beforeAll;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.injectMocks;
import static io.pivotal.security.helper.SpectrumHelper.itThrows;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class SignedCertificateGeneratorTest {
  private static final String SEPARATE_ISSUER_PRINCIPAL_STRING = "OU=cool org,C=\"adsf asdf\",ST=\'my fav state\',O=foo\\,inc.";

  private final Instant now = Instant.now();
  private final Calendar nowCalendar = Calendar.getInstance();

  @Mock
  DateTimeProvider timeProvider;

  @Mock
  RandomSerialNumberGenerator serialNumberGenerator;

  private X509Certificate generatedCert;
  private KeyPair issuerKeyPair;
  private X500Name issuerDistinguishedName;
  private X500Name subjectDistinguishedName;
  private KeyPair certKeyPair;
  private PrivateKey issuerPrivateKey;
  private CertificateSecretParameters inputParameters;
  private String isCA;

  @InjectMocks
  SignedCertificateGenerator subject;

  {
    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();

    beforeAll(() -> {
      Security.addProvider(bouncyCastleProvider);
    });

    beforeEach(injectMocks(this));

    beforeEach(() -> {
      subject.provider = bouncyCastleProvider;

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
          assertThat(new X500Name(generatedCert.getIssuerX500Principal().getName()),  equalTo(issuerDistinguishedName));
          assertThat(new X500Name(generatedCert.getSubjectX500Principal().getName()), equalTo(subjectDistinguishedName));
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

        it("sets the correct basic constraints based on type parameter", () -> {
          assertEquals(convertDerBytesToString(generatedCert.getExtensionValue(Extension.basicConstraints.getId())), isCA);
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
          inputParameters.addAlternativeNames("1.1.1.1", "example.com", "foo.pivotal.io", "*.pivotal.io");

          makeCert.run();

          assertThat(generatedCert.getSubjectAlternativeNames(), containsInAnyOrder(
              contains(7, "1.1.1.1"),
              contains(2, "example.com"),
              contains(2, "foo.pivotal.io"),
              contains(2, "*.pivotal.io")
          ));
        });

        itThrows("with invalid special DNS characters throws a validation exception", ParameterizedValidationException.class, () -> {
          inputParameters.addAlternativeNames("foo!@#$%^&*()_-+=.com");
          makeCert.run();
        });

        itThrows("with space character throws a validation exception", ParameterizedValidationException.class, () -> {
          inputParameters.addAlternativeNames("foo pivotal.io");
          makeCert.run();
        });

        itThrows("with invalid IP address throws a validation exception", ParameterizedValidationException.class, () -> {
          inputParameters.addAlternativeNames("1.2.3.999");
          makeCert.run();
        });

        // email addresses are allowed in certificate spec, but we do not allow them per PM requirements
        itThrows("with email address throws a validation exception", ParameterizedValidationException.class, () -> {
          inputParameters.addAlternativeNames("x@y.com");
          makeCert.run();
        });

        itThrows("with URL throws a validation exception", ParameterizedValidationException.class, () -> {
          inputParameters.addAlternativeNames("https://foo.com");
          makeCert.run();
        });
      });
    };

    describe("a generated issuer-signed childCertificate", () -> {
      beforeEach(() -> {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024); // doesn't matter for testing
        issuerKeyPair = generator.generateKeyPair();
        issuerPrivateKey = issuerKeyPair.getPrivate();

        certKeyPair = generator.generateKeyPair();
        inputParameters = new CertificateSecretParameters()
            .setCommonName("my test cert")
            .setCountry("US")
            .setState("CA")
            .setOrganization("credhub")
            .setDurationDays(10)
            .setType("certificate");
        isCA = "[]";
        subjectDistinguishedName = inputParameters.getDN();
        issuerDistinguishedName = new X500Name(SEPARATE_ISSUER_PRINCIPAL_STRING);
      });

      final ThrowingRunnable makeCert = () -> {
        generatedCert = subject.getSignedByIssuer(issuerDistinguishedName, issuerPrivateKey, certKeyPair, inputParameters);
      };

      describe("must behave like", validCertificateSuite.build(makeCert));

      it("is part of a trust chain with the ca", () -> {
        makeCert.run();
        final X509CertSelector target = new X509CertSelector();
        target.setCertificate(generatedCert);

        final TrustAnchor trustAnchor = new TrustAnchor(SEPARATE_ISSUER_PRINCIPAL_STRING, issuerKeyPair.getPublic(), null);
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
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024); // doesn't matter for testing
        issuerKeyPair = generator.generateKeyPair();

        certKeyPair = issuerKeyPair;
        inputParameters = new CertificateSecretParameters()
            .setCommonName("my test cert")
            .setCountry("US")
            .setState("CA")
            .setOrganization("credhub")
            .setDurationDays(10)
            .setType("root");
        isCA = "[TRUE]";
        subjectDistinguishedName = inputParameters.getDN();
        issuerDistinguishedName = subjectDistinguishedName;
      });

      describe("must behave like", validCertificateSuite.build(makeCert));
    });
  }

  interface ThrowingRunnable {
    void run() throws Exception;
  }

  interface SuiteBuilder {
    Spectrum.Block build(ThrowingRunnable makeCert);
  }

  private String convertDerBytesToString(byte [] data) {
    try {
      DEROctetString derOctetString = (DEROctetString) bytesToDerConversion(data);
      return bytesToDerConversion(derOctetString.getOctets()).toString();
    } catch(Exception e) {
      return "";
    }
  }

  private ASN1Primitive bytesToDerConversion(byte[] data) throws IOException {
    return data == null ? null : new ASN1InputStream(new ByteArrayInputStream(data)).readObject();
  }
}
