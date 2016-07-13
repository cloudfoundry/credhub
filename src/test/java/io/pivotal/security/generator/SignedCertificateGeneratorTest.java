package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import com.greghaskins.spectrum.SpringSpectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
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

@RunWith(SpringSpectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class SignedCertificateGeneratorTest {

  final Instant now = Instant.now();
  final Calendar nowCalendar = Calendar.getInstance();

  DateTimeProvider timeProvider;
  RandomSerialNumberGenerator serialNumberGenerator;

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

    describe("a generated certificate", () -> {
      Spectrum.Value<X509Certificate> generatedCert = Spectrum.value(X509Certificate.class);
      Spectrum.Value<KeyPair> issuerKeyPair = Spectrum.value(KeyPair.class);
      Spectrum.Value<X500Principal> caDn = Spectrum.value(X500Principal.class);
      Spectrum.Value<KeyPair> certKeyPair = Spectrum.value(KeyPair.class);

      beforeEach(() -> {
        caDn.value = new X500Principal("O=foo\\,inc.,ST=\'my fav state\', C=\"adsf asdf\",OU=cool org, EMAILADDRESS=x@y.com");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024); // doesn't matter for testing
        issuerKeyPair.value = generator.generateKeyPair();
        PrivateKey issuerPrivateKey = issuerKeyPair.value.getPrivate();

        certKeyPair.value = generator.generateKeyPair();
        CertificateSecretParameters inputParameters = new CertificateSecretParameters();
        inputParameters.setCommonName("my test cert");
        inputParameters.setCountry("US");
        inputParameters.setState("CA");
        inputParameters.setOrganization("credhub");
        inputParameters.setDurationDays(10);

        generatedCert.value = subject.getSignedByIssuer(caDn.value, issuerPrivateKey, certKeyPair.value, inputParameters);
      });

      it("is not null", () -> {
        assertNotNull(generatedCert);
      });

      it("the signature is valid", () -> {
        generatedCert.value.verify(issuerKeyPair.value.getPublic());
      });

      it("has the correct metadata", () -> {
        assertThat(generatedCert.value.getIssuerX500Principal(), equalTo(caDn.value));
        assertThat(generatedCert.value.getSubjectX500Principal().getName(), equalTo("CN=my test cert,C=US,ST=CA,O=credhub"));
      });

      it("is valid for the appropriate time range", () -> {
        assertThat(generatedCert.value.getNotBefore(), equalTo(Date.from(now.truncatedTo(ChronoUnit.SECONDS))));
        assertThat(generatedCert.value.getNotAfter(), equalTo(Date.from(now.plus(Duration.ofDays(10)).truncatedTo(ChronoUnit.SECONDS))));
      });

      it("has a random serial number", () -> {
        verify(serialNumberGenerator).generate();
        assertThat(generatedCert.value.getSerialNumber(), equalTo(BigInteger.valueOf(12)));
      });

      it("contains the public key", () -> {
        assertThat(generatedCert.value.getPublicKey(), equalTo(certKeyPair.value.getPublic()));
      });

      it("is part of a trust chain with the ca", () -> {
        final X509CertSelector target = new X509CertSelector();
        target.setCertificate(generatedCert.value);

        final TrustAnchor trustAnchor = new TrustAnchor(caDn.value, issuerKeyPair.value.getPublic(), null);
        final PKIXBuilderParameters builderParameters = new PKIXBuilderParameters(Collections.singleton(trustAnchor), target);

        final CertStore certStore = new JcaCertStoreBuilder()
            .addCertificate(new X509CertificateHolder(generatedCert.value.getEncoded()))
            .build();

        builderParameters.addCertStore(certStore);
        builderParameters.setRevocationEnabled(false);

        final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
        final CertPathBuilderResult builderResult = certPathBuilder.build(builderParameters);
        builderResult.getCertPath();
      });
    });
  }

  private void createAndInjectMocks() {
    // @Mock annotation doesn't seem to work, so do it manually
    timeProvider = Mockito.mock(DateTimeProvider.class);
    subject.timeProvider = timeProvider;
    serialNumberGenerator = Mockito.mock(RandomSerialNumberGenerator.class);
    subject.serialNumberGenerator = serialNumberGenerator;
  }
}