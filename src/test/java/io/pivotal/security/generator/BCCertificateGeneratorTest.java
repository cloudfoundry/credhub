package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.util.CurrentTimeProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.greghaskins.spectrum.Spectrum.let;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class BCCertificateGeneratorTest {
  private BCCertificateGenerator subject;

  private LibcryptoRsaKeyPairGenerator keyGenerator;
  private SignedCertificateGenerator signedCertificateGenerator;
  private CertificateAuthorityService certificateAuthorityService;
  private BouncyCastleProvider bouncyCastleProvider;

  private FakeKeyPairGenerator fakeKeyPairGenerator;

  private X500Name rootCaDn;
  private KeyPair rootCaKeyPair;
  private Certificate rootCa;
  private X509Certificate rootCaX509Certificate;

  private X500Name intermediateCaDn;
  private KeyPair intermediateCaKeyPair;
  private Certificate intermediateCa;
  private X509Certificate intermediateX509Certificate;

  private CertificateSecretParameters inputParameters;
  private X509Certificate childX509Certificate;

  {
    beforeEach(() -> {
      keyGenerator = mock(LibcryptoRsaKeyPairGenerator.class);
      signedCertificateGenerator = mock(SignedCertificateGenerator.class);
      certificateAuthorityService = mock(CertificateAuthorityService.class);
      bouncyCastleProvider = new BouncyCastleProvider();

      subject = new BCCertificateGenerator(keyGenerator, signedCertificateGenerator, certificateAuthorityService, bouncyCastleProvider);

      Security.addProvider(bouncyCastleProvider);

      fakeKeyPairGenerator = new FakeKeyPairGenerator();

      rootCaDn = new X500Name("O=foo,ST=bar,C=root");
      rootCaKeyPair = fakeKeyPairGenerator.generate();
      X509CertificateHolder caX509CertHolder = makeCert(rootCaKeyPair, rootCaKeyPair.getPrivate(), rootCaDn, rootCaDn, true);
      rootCaX509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caX509CertHolder);
      rootCa = new Certificate(
          null,
          CertificateFormatter.pemOf(rootCaX509Certificate),
          CertificateFormatter.pemOf(rootCaKeyPair.getPrivate())
      );

      inputParameters = new CertificateSecretParameters()
        .setOrganization("foo")
        .setState("bar")
        .setCaName("my-ca-name")
        .setCountry("mars")
        .setDurationDays(365);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("when CA exists", () -> {
      final Supplier<KeyPair> childCertificateKeyPair = let(() -> fakeKeyPairGenerator.generate());

      describe("and it is a root CA", () -> {
        beforeEach(() -> {
          when(certificateAuthorityService.findMostRecent("my-ca-name")).thenReturn(rootCa);

          when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair.get());

          X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
              childCertificateKeyPair.get(),
              rootCaKeyPair.getPrivate(),
              rootCaDn
          );

          childX509Certificate = new JcaX509CertificateConverter()
              .setProvider("BC")
              .getCertificate(childCertificateHolder);

          when(
              signedCertificateGenerator
                  .getSignedByIssuer(rootCaDn, rootCaKeyPair.getPrivate(), childCertificateKeyPair.get(), inputParameters)
          ).thenReturn(childX509Certificate);
        });

        it("generates a valid childCertificate", () -> {
          Certificate certificateSignedByRoot = subject.generateSecret(inputParameters);

          assertThat(certificateSignedByRoot.getCaCertificate(),
              equalTo(rootCa.getPublicKeyCertificate()));

          assertThat(certificateSignedByRoot.getPrivateKey(),
              equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.get().getPrivate())));

          assertThat(certificateSignedByRoot.getPublicKeyCertificate(),
              equalTo(CertificateFormatter.pemOf(childX509Certificate)));

          verify(keyGenerator, times(1)).generateKeyPair(2048);
        });

        it("generates a valid childCertificate when a key length is given", () -> {
          inputParameters.setKeyLength(4096);

          Certificate certificateSecret = subject.generateSecret(inputParameters);

          assertThat(certificateSecret, notNullValue());
          verify(keyGenerator, times(1)).generateKeyPair(4096);
        });
      });

      describe("and it is an intermediate CA", () -> {
        beforeEach(() -> {
          intermediateCaDn = new X500Name("O=foo,ST=bar,C=intermediate");
          intermediateCaKeyPair = fakeKeyPairGenerator.generate();
          X509CertificateHolder intermediateCaCertificateHolder = makeCert(intermediateCaKeyPair, rootCaKeyPair.getPrivate(), rootCaDn, intermediateCaDn, true);
          intermediateX509Certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(intermediateCaCertificateHolder);
          intermediateCa = new Certificate(
              null,
              CertificateFormatter.pemOf(intermediateX509Certificate),
              CertificateFormatter.pemOf(intermediateCaKeyPair.getPrivate())
          );
          when(certificateAuthorityService.findMostRecent("my-ca-name")).thenReturn(intermediateCa);

          when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair.get());

          X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
              childCertificateKeyPair.get(),
              intermediateCaKeyPair.getPrivate(),
              intermediateCaDn
          );

          childX509Certificate = new JcaX509CertificateConverter()
              .setProvider("BC")
              .getCertificate(childCertificateHolder);

          when(
              signedCertificateGenerator
                  .getSignedByIssuer(intermediateCaDn, intermediateCaKeyPair.getPrivate(), childCertificateKeyPair.get(), inputParameters)
          ).thenReturn(childX509Certificate);
        });

        it("generates a valid childCertificate", () -> {
          Certificate certificateSignedByIntermediate = subject.generateSecret(inputParameters);

          assertThat(certificateSignedByIntermediate.getCaCertificate(),
              equalTo(intermediateCa.getPublicKeyCertificate()));

          assertThat(certificateSignedByIntermediate.getPrivateKey(),
              equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.get().getPrivate())));

          assertThat(certificateSignedByIntermediate.getPublicKeyCertificate(),
              equalTo(CertificateFormatter.pemOf(childX509Certificate)));

          verify(keyGenerator, times(1)).generateKeyPair(2048);
        });
      });
    });

    describe("when the selfSign flag is set", () -> {
      final Supplier<X509Certificate> certificate = let(() ->
          new JcaX509CertificateConverter().setProvider("BC").getCertificate(generateX509SelfSignedCert())
      );

      beforeEach(() -> {
        inputParameters.setCaName(null);
        inputParameters.setSelfSigned(true);
        when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);
        when(signedCertificateGenerator.getSelfSigned(rootCaKeyPair, inputParameters)).thenReturn(certificate.get());
      });

      it("generates a valid self-signed certificate", () -> {
        Certificate certificateSecret = subject.generateSecret(inputParameters);
        assertThat(certificateSecret.getPrivateKey(),
                equalTo(CertificateFormatter.pemOf(rootCaKeyPair.getPrivate())));
        assertThat(certificateSecret.getPublicKeyCertificate(),
                equalTo(CertificateFormatter.pemOf(certificate.get())));
        assertThat(certificateSecret.getCaCertificate(), nullValue());
        verify(signedCertificateGenerator, times(1)).getSelfSigned(rootCaKeyPair, inputParameters);
      });
    });
  }

  private X509CertificateHolder generateX509SelfSignedCert() throws Exception {
    return makeCert(rootCaKeyPair, rootCaKeyPair.getPrivate(), rootCaDn, rootCaDn, false);
  }

  private X509CertificateHolder generateChildCertificateSignedByCa(KeyPair certKeyPair,
                                                                   PrivateKey caPrivateKey,
                                                                   X500Name caDn) throws Exception {
    return makeCert(certKeyPair, caPrivateKey, caDn, inputParameters.getDN(), false);
  }

  private X509CertificateHolder makeCert(KeyPair certKeyPair,
                                         PrivateKey caPrivateKey,
                                         X500Name caDn,
                                         X500Name subjectDN,
                                         boolean isCA) throws OperatorCreationException, NoSuchAlgorithmException, CertIOException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(certKeyPair.getPublic()
        .getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
        .build(caPrivateKey);

    CurrentTimeProvider currentTimeProvider = new CurrentTimeProvider();

    Instant now = currentTimeProvider.getNow().toInstant();

    X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
      caDn,
      BigInteger.TEN,
      Date.from(now),
      Date.from(now.plus(Duration.ofDays(365))),
      subjectDN,
      publicKeyInfo
    );
    x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));
    return x509v3CertificateBuilder.build(contentSigner);
  }
}
