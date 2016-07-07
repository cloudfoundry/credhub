package io.pivotal.security.generator;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.MockitoSpringTest;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.InMemoryAuthorityRepository;
import io.pivotal.security.view.CertificateSecret;
import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.util.CertificateFormatter;
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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.StringStartsWith.startsWith;
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
  SelfSignedCertificateGenerator selfSignedCertificateGenerator;

  @Mock
  SignedCertificateGenerator signedCertificateGenerator;

  @Mock
  InMemoryAuthorityRepository authorityRepository;

  @Before
  public void setUp() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  public void generateCertificateWithDefaultKeyLengthSucceeds() throws Exception {
    KeyPair expectedKeyPair = generateKeyPair();
    when(keyGenerator.generateKeyPair()).thenReturn(expectedKeyPair);

    CertificateSecretParameters inputParameters = new CertificateSecretParameters();
    X509Certificate caCert = generateX509Certificate(expectedKeyPair, "O=foo,ST=bar,C=mars");
    when(selfSignedCertificateGenerator.get(expectedKeyPair, inputParameters)).thenReturn(caCert);

    String expectedCert = CertificateFormatter.pemOf(caCert);
    String expectedPrivate = CertificateFormatter.pemOf(expectedKeyPair.getPrivate());

    CertificateSecret certificateSecret = subject.generateSecret(inputParameters);

    assertThat(certificateSecret, notNullValue());
    assertThat(certificateSecret.getCertificateBody().getCa(), nullValue());
    assertThat(certificateSecret.getCertificateBody().getPriv(), equalTo(expectedPrivate));
    assertThat(certificateSecret.getCertificateBody().getPub(), equalTo(expectedCert));
    Mockito.verify(keyGenerator).initialize(2048);
  }

  @Test
  public void generateCertSetsCustomKeyLength() throws Exception {
    KeyPair expectedKeyPair = generateKeyPair();
    when(keyGenerator.generateKeyPair()).thenReturn(expectedKeyPair);

    CertificateSecretParameters inputParameters = new CertificateSecretParameters();
    inputParameters.setKeyLength(1024);
    X509Certificate caCert = generateX509Certificate(expectedKeyPair, "O=foo,ST=bar,C=mars");
    when(selfSignedCertificateGenerator.get(expectedKeyPair, inputParameters)).thenReturn(caCert);

    subject.generateSecret(inputParameters);

    Mockito.verify(keyGenerator).initialize(1024);
  }

  @Test
  public void generateCertificateWithACaReturnsSignedChildCertificate() throws Exception {
    KeyPair certificateKeyPair = generateKeyPair();
    when(keyGenerator.generateKeyPair()).thenReturn(certificateKeyPair);

    String principle = "O=foo,ST=bar,C=mars";
    X500Principal caDn = new X500Principal(principle);
    KeyPair caKeyPair = generateKeyPair();
    NamedCertificateAuthority myCa = new NamedCertificateAuthority("my-ca");
    myCa.setPub(CertificateFormatter.pemOf(generateX509Certificate(caKeyPair, principle)));
    myCa.setPriv(CertificateFormatter.pemOf(caKeyPair.getPrivate()));
    when(authorityRepository.findOneByName("my-ca")).thenReturn(myCa);

    CertificateSecretParameters parameters = new CertificateSecretParameters();
    parameters.setCa("my-ca");

    X509CertificateHolder certificateHolder = getCertSignedByCa(certificateKeyPair, caKeyPair.getPrivate(), caDn);

    when(signedCertificateGenerator.get(caDn, caKeyPair.getPrivate(), certificateKeyPair, parameters))
        .thenReturn(new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder));

    CertificateSecret certificateSecret = subject.generateSecret(parameters);
    assertThat(certificateSecret.getCertificateBody().getCa(), nullValue());
    assertThat(certificateSecret.getCertificateBody().getPub(), startsWith("-----BEGIN CERTIFICATE-----"));
    assertThat(certificateSecret.getCertificateBody().getPriv(), startsWith("-----BEGIN RSA PRIVATE KEY-----"));
  }

  @Test
  public void generateCertificateWhenNoCaUsesDefaultCa() throws Exception {
    KeyPair certificateKeyPair = generateKeyPair();
    when(keyGenerator.generateKeyPair()).thenReturn(certificateKeyPair);
    String principle = "O=default,ST=default,C=default";
    KeyPair defaultCaKeyPair = generateKeyPair();
    NamedCertificateAuthority myCa = new NamedCertificateAuthority("default");

    myCa.setPub(CertificateFormatter.pemOf(generateX509Certificate(defaultCaKeyPair, principle)));
    myCa.setPriv(CertificateFormatter.pemOf(defaultCaKeyPair.getPrivate()));
    when(authorityRepository.findOneByName("default")).thenReturn(myCa);

    CertificateSecretParameters parameters = new CertificateSecretParameters();

    X500Principal caDn = new X500Principal(principle);
    X509CertificateHolder certificateHolder = getCertSignedByCa(certificateKeyPair, defaultCaKeyPair.getPrivate(), caDn);

    when(signedCertificateGenerator.get(caDn, defaultCaKeyPair.getPrivate(), certificateKeyPair, parameters))
        .thenReturn(new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder));

    CertificateSecret certificateSecret = subject.generateSecret(parameters);
    assertThat(certificateSecret.getCertificateBody().getCa(), nullValue());
    assertThat(certificateSecret.getCertificateBody().getPub(), startsWith("-----BEGIN CERTIFICATE-----"));
    assertThat(certificateSecret.getCertificateBody().getPriv(), startsWith("-----BEGIN RSA PRIVATE KEY-----"));
  }

  private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(1024); // doesn't matter for testing
    return generator.generateKeyPair();
  }

  private X509Certificate generateX509Certificate(KeyPair expectedKeyPair, String principle) throws CertificateEncodingException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
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