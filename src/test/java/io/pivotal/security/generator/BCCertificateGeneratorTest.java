package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.CertificateSecret;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
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
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.validation.ValidationException;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class BCCertificateGeneratorTest {

  @InjectMocks
  @Autowired
  private BCCertificateGenerator subject;

  @Mock
  KeyPairGenerator keyGenerator;

  @Mock
  SignedCertificateGenerator signedCertificateGenerator;

  @Mock
  InMemoryAuthorityRepository authorityRepository;

  private KeyPair certificateKeyPair;
  private X500Principal caDn;
  private KeyPair caKeyPair;
  private String caPrinciple;
  private NamedCertificateAuthority defaultNamedCA;
  private CertificateSecretParameters inputParameters;
  private X509CertificateHolder certSignedByCa;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      Security.addProvider(new BouncyCastleProvider());
      certificateKeyPair = generateKeyPair();

      caPrinciple = "O=foo,ST=bar,C=mars";
      caDn = new X500Principal(caPrinciple);
      caKeyPair = generateKeyPair();

      X509Certificate caX509Cert = generateX509Certificate(caKeyPair, caPrinciple);

      defaultNamedCA = new NamedCertificateAuthority("default");
      defaultNamedCA.setCertificate(CertificateFormatter.pemOf(caX509Cert));
      defaultNamedCA.setPrivateKey(CertificateFormatter.pemOf(caKeyPair.getPrivate()));

      when(keyGenerator.generateKeyPair()).thenReturn(certificateKeyPair);

      inputParameters = new CertificateSecretParameters();
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
        when(signedCertificateGenerator.getSignedByIssuer(caDn, caKeyPair.getPrivate(), certificateKeyPair, inputParameters))
            .thenReturn(new JcaX509CertificateConverter().setProvider("BC").getCertificate(certSignedByCa));
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

  private X509Certificate generateX509Certificate(KeyPair expectedKeyPair, String principle) throws Exception {
    final X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
    final X500Principal dnName = new X500Principal(principle);
    certGen.setSerialNumber(BigInteger.valueOf(1));
    Instant instant = Instant.now();
    final Date now = Date.from(instant);
    final Date later = Date.from(instant.plus(365, ChronoUnit.DAYS));
    certGen.setIssuerDN(dnName);
    certGen.setNotBefore(now);
    certGen.setNotAfter(later);
    certGen.setSubjectDN(dnName);
    certGen.setPublicKey(expectedKeyPair.getPublic());
    certGen.setSignatureAlgorithm("SHA256withRSA");
    return certGen.generate(expectedKeyPair.getPrivate(), "BC");
  }

  private X509CertificateHolder getCertSignedByCa(KeyPair certificateKeyPair, PrivateKey caPrivateKey, X500Principal caDn) throws OperatorCreationException {
    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
    SubjectPublicKeyInfo publicKeyInfo = new SubjectPublicKeyInfo(sigAlgId, certificateKeyPair.getPublic().getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(caPrivateKey);

    Instant now = Instant.now();
    return new X509v1CertificateBuilder(
        new X500Name(caDn.getName()),
        BigInteger.valueOf(2),
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(365))),
        new X500Name("C=US,CN=Subject"),
        publicKeyInfo
    ).build(contentSigner);
  }
}