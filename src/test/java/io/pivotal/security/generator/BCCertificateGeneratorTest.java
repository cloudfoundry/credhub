package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.entity.SecretEncryptionHelper;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.CertificateAuthorityView;
import io.pivotal.security.view.CertificateView;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class BCCertificateGeneratorTest {

  private static final int KEY_LENGTH_FOR_TESTING = 1024;

  @Autowired
  private BCCertificateGenerator subject;

  @MockBean
  private SignedCertificateGenerator signedCertificateGenerator;

  @MockBean
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  FakeKeyPairGenerator fakeKeyPairGenerator;

  @MockBean
  CertificateAuthorityDataService certificateAuthorityDataService;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  @MockBean
  RandomSerialNumberGenerator randomSerialNumberGenerator;

  @SpyBean
  SecretEncryptionHelper secretEncryptionHelper;

  private KeyPair childCertificateKeyPair;
  private X500Name caDn;
  private KeyPair caKeyPair;
  private NamedCertificateAuthority defaultNamedCA;
  private CertificateSecretParameters inputParameters;
  private X509CertificateHolder childCertificateHolder;
  private X509Certificate caX509Cert;
  private X509Certificate childCertificate;
  private String privateKey;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());

      when(currentTimeProvider.getNow()).thenReturn(new Calendar.Builder().setInstant(22233333L).build());
      when(randomSerialNumberGenerator.generate()).thenReturn(BigInteger.TEN);

      caDn = new X500Name("O=foo,ST=bar,C=mars");
      caKeyPair = fakeKeyPairGenerator.generate();
      X509CertificateHolder caX509CertHolder = generateX509CertificateAuthority();
      caX509Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caX509CertHolder);
      privateKey = CertificateFormatter.pemOf(caKeyPair.getPrivate());
      defaultNamedCA = new NamedCertificateAuthority("default");
      defaultNamedCA
          .setCertificate(CertificateFormatter.pemOf(caX509Cert));

      defaultNamedCA.setEncryptedValue("fake-encrypted-value".getBytes());
      defaultNamedCA.setNonce("fake-nonce".getBytes());

      doReturn(privateKey).when(secretEncryptionHelper).retrieveClearTextValue(defaultNamedCA);

      inputParameters = new CertificateSecretParameters()
        .setOrganization("foo")
        .setState("bar")
        .setCountry("mars")
        .setDurationDays(365);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("when there is no default ca", () -> {
      it("throws a validation exception", () -> {
        CertificateSecretParameters inputParameters = new CertificateSecretParameters();
        try {
          subject.generateSecret(inputParameters);
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.default_ca_required"));
        }
      });

      it("throws the correct validation exception when default is explicitly requested", () -> {
        CertificateSecretParameters inputParameters = new CertificateSecretParameters();
        try {
          inputParameters.setCaName("default");
          subject.generateSecret(inputParameters);
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.default_ca_required"));
        }
      });
    });

    describe("when a CA does not exist", () -> {
      it("throws a validation exception when attempting to sign a certificate with that CA", () -> {
        inputParameters.setCaName("nonexistentCA");
        try {
          subject.generateSecret(inputParameters);
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.ca_not_found_for_certificate_generation"));
        }
      });
    });

    describe("when a default CA exists", () -> {
      beforeEach(() -> {
        childCertificateKeyPair = fakeKeyPairGenerator.generate();
        when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair);
        when(certificateAuthorityDataService.findMostRecent("default")).thenReturn(defaultNamedCA);
        childCertificateHolder = generateChildCertificateSignedByCa(
            childCertificateKeyPair, caKeyPair.getPrivate(), caDn);
        childCertificate = new JcaX509CertificateConverter()
            .setProvider("BC").getCertificate(childCertificateHolder);
        when(signedCertificateGenerator.getSignedByIssuer(caDn, caKeyPair.getPrivate(),
            childCertificateKeyPair, inputParameters)).thenReturn(childCertificate);
      });

      it("generates a valid childCertificate", () -> {
        CertificateView certificateSecret = subject.generateSecret(inputParameters);

        assertThat(certificateSecret.getCertificateBody().getCa(),
            equalTo(defaultNamedCA.getCertificate()));
        assertThat(certificateSecret.getCertificateBody().getPrivateKey(),
            equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.getPrivate())));
        assertThat(certificateSecret.getCertificateBody().getCertificate(),
            equalTo(CertificateFormatter.pemOf(childCertificate)));
        verify(keyGenerator, times(1)).generateKeyPair(2048);
      });

      describe("when a key length is given", () -> {
        beforeEach(() -> inputParameters.setKeyLength(4096));

        it("generates a valid childCertificate", () -> {
          CertificateView certificateSecret = subject.generateSecret(inputParameters);

          assertThat(certificateSecret, notNullValue());
          verify(keyGenerator, times(1)).generateKeyPair(4096);
        });
      });
    });

    describe("when generating a self signed root childCertificate authority", () -> {
      it("generates a valid root childCertificate authority", () -> {
        inputParameters.setKeyLength(KEY_LENGTH_FOR_TESTING);
        when(keyGenerator.generateKeyPair(anyInt())).thenReturn(caKeyPair);
        when(signedCertificateGenerator.getSelfSigned(caKeyPair, inputParameters)).thenReturn(caX509Cert);

        CertificateAuthorityView certificateAuthorityView = subject.generateCertificateAuthority(inputParameters);
        verify(keyGenerator, times(1)).generateKeyPair(KEY_LENGTH_FOR_TESTING);

        assertThat(certificateAuthorityView.getCertificateAuthorityBody().getCertificate(),
            equalTo(defaultNamedCA.getCertificate()));
        assertThat(certificateAuthorityView.getCertificateAuthorityBody().getPrivateKey(),
            equalTo(privateKey));
      });
    });
  }

  private X509CertificateHolder generateX509CertificateAuthority() throws Exception {
    return makeCert(caKeyPair, caKeyPair.getPrivate(), caDn, caDn);
  }

  private X509CertificateHolder generateChildCertificateSignedByCa(KeyPair certKeyPair,
                                                                   PrivateKey caPrivateKey,
                                                                   X500Name caDn) throws Exception {
    return makeCert(certKeyPair, caPrivateKey, caDn, inputParameters.getDN());
  }

  private X509CertificateHolder makeCert(KeyPair certKeyPair, PrivateKey caPrivateKey,
                                         X500Name caDn, X500Name subjectDN) throws OperatorCreationException, NoSuchAlgorithmException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(certKeyPair.getPublic()
        .getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
        .build(caPrivateKey);

    Instant now = currentTimeProvider.getNow().toInstant();

    return new X509v3CertificateBuilder(
        caDn,
        BigInteger.TEN,
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(365))),
        subjectDN,
        publicKeyInfo
    ).build(contentSigner);
  }
}
