package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.CertificateSecret;
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

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;

import javax.validation.ValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class BCCertificateGeneratorTest {

  @InjectMocks
  @Autowired
  private BCCertificateGenerator subject;

  @InjectMocks
  @Autowired
  private SignedCertificateGenerator signedCertificateGenerator;

  @Mock
  KeyPairGenerator keyGenerator;

  @Mock
  InMemoryAuthorityRepository authorityRepository;

  @Mock
  DateTimeProvider dateTimeProvider;

  @Mock
  RandomSerialNumberGenerator randomSerialNumberGenerator;

  private KeyPair certificateKeyPair;
  private X500Name caDn;
  private KeyPair caKeyPair;
  private NamedCertificateAuthority defaultNamedCA;
  private CertificateSecretParameters inputParameters;
  private X509CertificateHolder certSignedByCa;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(dateTimeProvider.getNow()).thenReturn(new Calendar.Builder().setInstant(22233333L).build());
      when(randomSerialNumberGenerator.generate()).thenReturn(BigInteger.TEN);
      Security.addProvider(new BouncyCastleProvider());
      certificateKeyPair = generateKeyPair();

      caDn = new X500Name("C=mars,ST=bar,O=foo");
      caKeyPair = generateKeyPair();
      X509CertificateHolder caX509CertHolder = generateX509Certificate(caKeyPair);
      X509Certificate caX509Cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caX509CertHolder);
      defaultNamedCA = new NamedCertificateAuthority("default");
      defaultNamedCA.setCertificate(CertificateFormatter.pemOf(caX509Cert));
      defaultNamedCA.setPrivateKey(CertificateFormatter.pemOf(caKeyPair.getPrivate()));

      when(keyGenerator.generateKeyPair()).thenReturn(certificateKeyPair);

      inputParameters = new CertificateSecretParameters()
        .setOrganization("foo")
        .setState("bar")
        .setCountry("mars")
        .setDurationDays(365);
    });

    afterEach(() -> {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    });

    it("throws a validation exception when there is no default ca", () -> {
      CertificateSecretParameters inputParameters = new CertificateSecretParameters();
      try {
        subject.generateSecret(inputParameters);
        fail();
      } catch (ValidationException ve) {
        assertThat(ve.getMessage(), equalTo("error.default_ca_required"));
      }
    });

    describe("when a default CA exists", () -> {
      beforeEach(() -> {
        when(authorityRepository.findOneByName("default")).thenReturn(defaultNamedCA);

        certSignedByCa = getCertSignedByCa(certificateKeyPair, caKeyPair.getPrivate(), caDn);
      });

      it("generates a valid certificate", () -> {
        CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

        assertThat(certificateSecret.getCertificateBody().getRoot(), equalTo(defaultNamedCA.getCertificate()));
        assertThat(certificateSecret.getCertificateBody().getPrivateKey(),
            equalTo(CertificateFormatter.pemOf(certificateKeyPair.getPrivate())));
        assertThat(certificateSecret.getCertificateBody().getCertificate(),
            equalTo(CertificateFormatter.pemOf(new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(certSignedByCa))));
        Mockito.verify(keyGenerator, times(1)).initialize(BcKeyPairGenerator.DEFAULT_KEY_LENGTH);
      });

      describe("when a key length is given", () -> {
        beforeEach(() -> {
          inputParameters.setKeyLength(2048);
        });

        it("generates a valid certificate", () -> {
          CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

          assertThat(certificateSecret, notNullValue());
          Mockito.verify(keyGenerator, times(1)).initialize(2048);
        });
      });
    });
  }

  private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(1024); // doesn't matter for testing
    return generator.generateKeyPair();
  }

  private X509CertificateHolder generateX509Certificate(KeyPair expectedKeyPair) throws Exception {
    return makeCert(certificateKeyPair, expectedKeyPair.getPrivate(), caDn, caDn);
  }

  private X509CertificateHolder getCertSignedByCa(KeyPair certificateKeyPair, PrivateKey caPrivateKey, X500Name caDn) throws Exception {
    return makeCert(certificateKeyPair, caPrivateKey, caDn, inputParameters.getDN());
  }

  private X509CertificateHolder makeCert(KeyPair certificateKeyPair, PrivateKey caPrivateKey, X500Name caDn, X500Name subjectDN) throws OperatorCreationException, NoSuchAlgorithmException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(certificateKeyPair.getPublic().getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caPrivateKey);

    Instant now = dateTimeProvider.getNow().toInstant();

    return new X509v3CertificateBuilder(
        caDn,
        randomSerialNumberGenerator.generate(),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(365))),
        subjectDN,
        publicKeyInfo
    ).build(contentSigner);
  }
}