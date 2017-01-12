package io.pivotal.security.generator;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.secret.CertificateAuthority;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
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
import org.springframework.test.context.ActiveProfiles;

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

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class BCCertificateAuthorityGeneratorTest {

  private static final int KEY_LENGTH_FOR_TESTING = 1024;

  @Autowired
  private BCCertificateAuthorityGenerator subject;

  @MockBean
  private SignedCertificateGenerator signedCertificateGenerator;

  @MockBean
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  FakeKeyPairGenerator fakeKeyPairGenerator;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  @MockBean
  RandomSerialNumberGenerator randomSerialNumberGenerator;

  private X500Name caDn;
  private KeyPair caKeyPair;
  private NamedCertificateAuthority defaultNamedCA;
  private CertificateSecretParameters inputParameters;
  private X509Certificate caX509Cert;
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

      inputParameters = new CertificateSecretParameters()
        .setOrganization("foo")
        .setState("bar")
        .setCountry("mars")
        .setDurationDays(365);
    });

    afterEach(() -> Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME));

    describe("when generating a self signed root childCertificate authority", () -> {
      it("generates a valid root childCertificate authority", () -> {
        inputParameters.setKeyLength(KEY_LENGTH_FOR_TESTING);
        when(keyGenerator.generateKeyPair(anyInt())).thenReturn(caKeyPair);
        when(signedCertificateGenerator.getSelfSigned(caKeyPair, inputParameters)).thenReturn(caX509Cert);

        CertificateAuthority certificateAuthority = subject.generateSecret(inputParameters);
        verify(keyGenerator, times(1)).generateKeyPair(KEY_LENGTH_FOR_TESTING);

        assertThat(certificateAuthority.getCertificate(),
            equalTo(defaultNamedCA.getCertificate()));
        assertThat(certificateAuthority.getPrivateKey(),
            equalTo(privateKey));
      });
    });
  }

  private X509CertificateHolder generateX509CertificateAuthority() throws Exception {
    return makeCert(caKeyPair, caKeyPair.getPrivate(), caDn, caDn);
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
