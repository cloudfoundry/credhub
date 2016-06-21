package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.model.CertificateSecret;
import io.pivotal.security.model.CertificateSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
public class BCCertificateGeneratorTest extends MockitoSpringTest {

  @InjectMocks
  @Autowired
  private BCCertificateGenerator subject;

  @Mock
  KeyPairGenerator keyGenerator;

  @Mock
  RootCertificateProvider rootCertificateProvider;

  @Before
  public void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void generateCertificateWithDefaultKeyLengthSucceeds() throws Exception {
    KeyPair expectedKeyPair = generateKeyPair(2048);
    when(keyGenerator.generateKeyPair()).thenReturn(expectedKeyPair);

    CertificateSecretParameters inputParameters = new CertificateSecretParameters();
    X509Certificate caCert = generateX509Certificate(expectedKeyPair);
    when(rootCertificateProvider.get(expectedKeyPair, inputParameters)).thenReturn(caCert);

    String expectedCert = CertificateFormatter.pemOf(caCert);
    String expectedPrivate = CertificateFormatter.pemOf(expectedKeyPair.getPrivate());

    CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

    assertThat(certificateSecret, notNullValue());
    assertThat(certificateSecret.getCertificateBody().getCa(), nullValue());
    assertThat(certificateSecret.getCertificateBody().getPriv(), equalTo(expectedPrivate));
    assertThat(certificateSecret.getCertificateBody().getPub(), equalTo(expectedCert));
  }

  @Test
  public void generateCertSetsCustomKeyLength() throws Exception {

    int keyLength = 1024;
    KeyPair expectedKeyPair = generateKeyPair(keyLength);
    when(keyGenerator.generateKeyPair()).thenReturn(expectedKeyPair);

    CertificateSecretParameters inputParameters = new CertificateSecretParameters();
    inputParameters.setKeyLength(keyLength);
    X509Certificate caCert = generateX509Certificate(expectedKeyPair);
    when(rootCertificateProvider.get(expectedKeyPair, inputParameters)).thenReturn(caCert);

//    String expectedPrivate = CertificateFormatter.pemOf(expectedKeyPair.getPrivate());

    CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

    String priv = certificateSecret.getCertificateBody().getPriv();
    PrivateKey privKey = translateFromPem(priv);
    KeyFactory keyFac = KeyFactory.getInstance("RSA", "BC");
    RSAPrivateKeySpec privateKeySpec = keyFac.getKeySpec(privKey, RSAPrivateKeySpec.class);
//    RSAPublicKeySpec publicKeySpec = keyFac.getKeySpec(keyPair.getPublic(),
//        RSAPublicKeySpec.class);
//
    assertThat(privateKeySpec.getModulus().bitLength(), equalTo(inputParameters.getKeyLength()));
    //assertThat(publicKeySpec.getModulus().bitLength(), equalTo(2048));

  }

  private PrivateKey translateFromPem(String privateKeyPEM) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
    privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
    privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
    byte[] encoded = Base64.decodeBase64(privateKeyPEM);
    KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
    return kf.generatePrivate(keySpec);
  }

  private KeyPair generateKeyPair(int keyLength) throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(keyLength);
    return generator.generateKeyPair();
  }

  private X509Certificate generateX509Certificate(KeyPair expectedKeyPair) throws CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    final X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
    final X500Principal dnName = new X500Principal("O=foo,ST=bar,C=mars");
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

}