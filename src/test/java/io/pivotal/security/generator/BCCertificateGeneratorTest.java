package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.CertificateSecret;
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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

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
import static org.mockito.Mockito.times;
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
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class BCCertificateGeneratorTest {

  private static final int KEY_LENGTH_FOR_TESTING = 1024;

  @InjectMocks
  @Autowired
  private BCCertificateGenerator subject;

  @Mock
  private SignedCertificateGenerator signedCertificateGenerator;

  @Mock
  BCRsaKeyPairGenerator keyGenerator;

  @Autowired
  FakeKeyPairGenerator fakeKeyPairGenerator;

  @Mock
  CertificateAuthorityRepository authorityRepository;

  @Mock
  DateTimeProvider dateTimeProvider;

  @Mock
  RandomSerialNumberGenerator randomSerialNumberGenerator;

  private KeyPair childCertificateKeyPair;
  private X500Name caDn;
  private KeyPair caKeyPair;
  private NamedCertificateAuthority defaultNamedCA;
  private CertificateSecretParameters inputParameters;
  private X509CertificateHolder childCertificateHolder;
  private X509Certificate caX509Cert;
  private X509Certificate childCertificate;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());

      when(dateTimeProvider.getNow()).thenReturn(new Calendar.Builder().setInstant(22233333L).build());
      when(randomSerialNumberGenerator.generate()).thenReturn(BigInteger.TEN);

      caDn = new X500Name("O=foo,ST=bar,C=mars");
      caKeyPair = fakeKeyPairGenerator.generate();
      X509CertificateHolder caX509CertHolder = generateX509CertificateAuthority();
      caX509Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caX509CertHolder);
      defaultNamedCA = new NamedCertificateAuthority("default");
      defaultNamedCA.setCertificate(CertificateFormatter.pemOf(caX509Cert));
      defaultNamedCA.setPrivateKey(CertificateFormatter.pemOf(caKeyPair.getPrivate()));

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
          inputParameters.setCa("default");
          subject.generateSecret(inputParameters);
          fail();
        } catch (ParameterizedValidationException ve) {
          assertThat(ve.getMessage(), equalTo("error.default_ca_required"));
        }
      });
    });

    describe("when a CA does not exist", () -> {
      it("throws a validation exception when attempting to sign a certificate with that CA", () -> {
        inputParameters.setCa("nonexistentCA");
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
        when(authorityRepository.findOneByNameIgnoreCase("default")).thenReturn(defaultNamedCA);
        childCertificateHolder = generateChildCertificateSignedByCa(
            childCertificateKeyPair, caKeyPair.getPrivate(), caDn);
        childCertificate = new JcaX509CertificateConverter()
            .setProvider("BC").getCertificate(childCertificateHolder);
        when(signedCertificateGenerator.getSignedByIssuer(caDn, caKeyPair.getPrivate(),
            childCertificateKeyPair, inputParameters)).thenReturn(childCertificate);
      });

      it("generates a valid childCertificate", () -> {
        CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

        assertThat(certificateSecret.getCertificateBody().getCa(),
            equalTo(defaultNamedCA.getCertificate()));
        assertThat(certificateSecret.getCertificateBody().getPrivateKey(),
            equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.getPrivate())));
        assertThat(certificateSecret.getCertificateBody().getCertificate(),
            equalTo(CertificateFormatter.pemOf(childCertificate)));
        Mockito.verify(keyGenerator, times(1)).generateKeyPair(2048);
      });

      describe("when a key length is given", () -> {
        beforeEach(() -> inputParameters.setKeyLength(4096));

        it("generates a valid childCertificate", () -> {
          CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

          assertThat(certificateSecret, notNullValue());
          Mockito.verify(keyGenerator, times(1)).generateKeyPair(4096);
        });
      });
    });

    describe("when generating a self signed root childCertificate authority", () -> {
      it("generates a valid root childCertificate authority", () -> {
        inputParameters.setKeyLength(KEY_LENGTH_FOR_TESTING);
        when(keyGenerator.generateKeyPair(anyInt())).thenReturn(caKeyPair);
        when(signedCertificateGenerator.getSelfSigned(caKeyPair, inputParameters)).thenReturn(caX509Cert);

        CertificateAuthority certificateAuthority = subject.generateCertificateAuthority(inputParameters);
        Mockito.verify(keyGenerator, times(1)).generateKeyPair(KEY_LENGTH_FOR_TESTING);

        assertThat(certificateAuthority.getCertificateAuthorityBody().getCertificate(),
            equalTo(defaultNamedCA.getCertificate()));
        assertThat(certificateAuthority.getCertificateAuthorityBody().getPrivateKey(),
            equalTo(defaultNamedCA.getPrivateKey()));
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

    Instant now = dateTimeProvider.getNow().toInstant();

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
