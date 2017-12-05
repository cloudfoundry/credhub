package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.data.CertificateAuthorityService;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters;
import org.cloudfoundry.credhub.service.PermissionCheckingService;
import org.cloudfoundry.credhub.util.CertificateFormatter;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static org.assertj.core.api.Assertions.fail;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CertificateGeneratorTest {

  private CertificateGenerator subject;

  private LibcryptoRsaKeyPairGenerator keyGenerator;
  private SignedCertificateGenerator signedCertificateGenerator;
  private CertificateAuthorityService certificateAuthorityService;

  private FakeKeyPairGenerator fakeKeyPairGenerator;

  private X500Name rootCaDn;
  private X500Name signeeDn;
  private KeyPair rootCaKeyPair;
  private X509Certificate rootCaX509Certificate;
  private CertificateCredentialValue rootCa;

  private CertificateGenerationParameters inputParameters;
  private CertificateGenerationRequestParameters generationParameters;
  private X509Certificate childX509Certificate;
  private PermissionCheckingService permissionCheckingService;
  private UserContext userContext;

  @Before
  public void beforeEach() throws Exception {
    keyGenerator = mock(LibcryptoRsaKeyPairGenerator.class);
    signedCertificateGenerator = mock(SignedCertificateGenerator.class);
    certificateAuthorityService = mock(CertificateAuthorityService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    userContext = mock(UserContext.class);

    subject = new CertificateGenerator(
        keyGenerator,
        signedCertificateGenerator,
        certificateAuthorityService
    );

    when(permissionCheckingService.hasPermission(anyString(), anyString(), any())).thenReturn(true);

    fakeKeyPairGenerator = new FakeKeyPairGenerator();

    rootCaDn = new X500Name("O=foo,ST=bar,C=root");
    signeeDn = new X500Name("O=foo,ST=bar,C=mars");
    rootCaKeyPair = fakeKeyPairGenerator.generate();
    X509CertificateHolder caX509CertHolder = makeCert(rootCaKeyPair, rootCaKeyPair.getPrivate(),
        rootCaDn, rootCaDn, true);
    rootCaX509Certificate = new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(caX509CertHolder);
    rootCa = new CertificateCredentialValue(
        null,
        CertificateFormatter.pemOf(rootCaX509Certificate),
        CertificateFormatter.pemOf(rootCaKeyPair.getPrivate()),
        null);

    generationParameters = new CertificateGenerationRequestParameters();
    generationParameters.setOrganization("foo");
    generationParameters.setState("bar");
    generationParameters.setCaName("my-ca-name");
    generationParameters.setCountry("mars");
    generationParameters.setDuration(365);

    inputParameters = new CertificateGenerationParameters(generationParameters);
  }

  @Test
  public void whenCAExists_andItIsARootCA_aValidChildCertificateIsGenerated() throws Exception {
    final KeyPair childCertificateKeyPair = setupKeyPair();
    setupMocksForRootCA(childCertificateKeyPair);

    CertificateCredentialValue certificateSignedByRoot = subject.generateCredential(inputParameters);

    assertThat(certificateSignedByRoot.getCa(),
        equalTo(rootCa.getCertificate()));

    assertThat(certificateSignedByRoot.getPrivateKey(),
        equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.getPrivate())));

    assertThat(certificateSignedByRoot.getCertificate(),
        equalTo(CertificateFormatter.pemOf(childX509Certificate)));

    assertThat(certificateSignedByRoot.getCaName(), equalTo("/my-ca-name"));

    verify(keyGenerator, times(1)).generateKeyPair(2048);

  }

  @Test
  public void whenCAExists_andItIsARootCA_aValidChildCertificateIsGeneratedWithTheProvidedKeyLength()
      throws Exception {
    final KeyPair childCertificateKeyPair = setupKeyPair();
    setupMocksForRootCA(childCertificateKeyPair);

    generationParameters.setKeyLength(4096);
    CertificateGenerationParameters params = new CertificateGenerationParameters(generationParameters);

    when(
        signedCertificateGenerator
            .getSignedByIssuer(childCertificateKeyPair, params, rootCaX509Certificate, rootCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);

    CertificateCredentialValue certificate = subject.generateCredential(params);

    assertThat(certificate, notNullValue());
    verify(keyGenerator, times(1)).generateKeyPair(4096);
  }

  @Test
  public void whenCAExists_andItIsAIntermediateCA_aValidChildCertificateIsGenerated()
      throws Exception {
    final KeyPair childCertificateKeyPair = setupKeyPair();

    X500Name intermediateCaDn = new X500Name("O=foo,ST=bar,C=intermediate");
    KeyPair intermediateCaKeyPair = fakeKeyPairGenerator.generate();
    X509CertificateHolder intermediateCaCertificateHolder = makeCert(intermediateCaKeyPair,
        rootCaKeyPair.getPrivate(), rootCaDn, intermediateCaDn, true);
    X509Certificate intermediateX509Certificate = new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(intermediateCaCertificateHolder);
    CertificateCredentialValue intermediateCa = new CertificateCredentialValue(
        null,
        CertificateFormatter.pemOf(intermediateX509Certificate),
        CertificateFormatter.pemOf(intermediateCaKeyPair.getPrivate()),
        null);
    when(certificateAuthorityService.findActiveVersion("/my-ca-name")).thenReturn(intermediateCa);

    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair);

    X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
        childCertificateKeyPair,
        intermediateCaKeyPair.getPrivate(),
        intermediateCaDn
    );

    childX509Certificate = new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(childCertificateHolder);

    when(
        signedCertificateGenerator
            .getSignedByIssuer(childCertificateKeyPair, inputParameters, intermediateX509Certificate, intermediateCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);


    CertificateCredentialValue certificateSignedByIntermediate = subject.generateCredential(inputParameters);

    assertThat(certificateSignedByIntermediate.getCa(),
        equalTo(intermediateCa.getCertificate()));

    assertThat(certificateSignedByIntermediate.getPrivateKey(),
        equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.getPrivate())));

    assertThat(certificateSignedByIntermediate.getCertificate(),
        equalTo(CertificateFormatter.pemOf(childX509Certificate)));

    verify(keyGenerator, times(1)).generateKeyPair(2048);
  }

  @Test
  public void whenSelfSignIsTrue_itGeneratesAValidSelfSignedCertificate() throws Exception {
    final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(generateX509SelfSignedCert());

    generationParameters.setCaName(null);
    generationParameters.setSelfSigned(true);
    inputParameters = new CertificateGenerationParameters(generationParameters);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);
    when(signedCertificateGenerator.getSelfSigned(rootCaKeyPair, inputParameters))
        .thenReturn(certificate);

    CertificateCredentialValue certificateCredential = subject.generateCredential(inputParameters);
    assertThat(certificateCredential.getPrivateKey(),
        equalTo(CertificateFormatter.pemOf(rootCaKeyPair.getPrivate())));
    assertThat(certificateCredential.getCertificate(),
        equalTo(CertificateFormatter.pemOf(certificate)));
    assertThat(certificateCredential.getCa(), nullValue());
    verify(signedCertificateGenerator, times(1)).getSelfSigned(rootCaKeyPair, inputParameters);
  }

  @Test
  public void whenTheCADoesNotHaveAPrivateKey_itThrowsAnException() throws Exception {
    CertificateGenerationRequestParameters parameters = new CertificateGenerationRequestParameters();
    parameters.setCaName("/ca-without-private-key");
    parameters.setKeyLength(2048);
    parameters.setSelfSigned(false);

    CertificateCredentialValue caWithoutPrivateKey = mock(CertificateCredentialValue.class);
    when(certificateAuthorityService.findActiveVersion("/ca-without-private-key"))
        .thenReturn(caWithoutPrivateKey);

    when(caWithoutPrivateKey.getPrivateKey()).thenReturn(null);

    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);

    try {
      subject.generateCredential(new CertificateGenerationParameters(parameters));
      fail("Should throw exception");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.ca_missing_private_key"));
    }
  }

  private X509CertificateHolder generateX509SelfSignedCert() throws Exception {
    return makeCert(rootCaKeyPair, rootCaKeyPair.getPrivate(), rootCaDn, rootCaDn, false);
  }

  private X509CertificateHolder generateChildCertificateSignedByCa(KeyPair certKeyPair,
      PrivateKey caPrivateKey,
      X500Name caDn) throws Exception {
    return makeCert(certKeyPair, caPrivateKey, caDn, signeeDn, false);
  }

  private X509CertificateHolder makeCert(KeyPair certKeyPair,
      PrivateKey caPrivateKey,
      X500Name caDn,
      X500Name subjectDn,
      boolean isCa) throws OperatorCreationException, NoSuchAlgorithmException, CertIOException {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(certKeyPair.getPublic()
        .getEncoded());
    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(caPrivateKey);

    CurrentTimeProvider currentTimeProvider = new CurrentTimeProvider();

    Instant now = currentTimeProvider.getNow().toInstant();

    X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
        caDn,
        BigInteger.TEN,
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(365))),
        subjectDn,
        publicKeyInfo
    );
    x509v3CertificateBuilder
        .addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
    return x509v3CertificateBuilder.build(contentSigner);
  }

  private void setupMocksForRootCA(KeyPair childCertificateKeyPair) throws Exception {
    when(certificateAuthorityService.findActiveVersion("/my-ca-name")).thenReturn(rootCa);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair);
    X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
        childCertificateKeyPair,
        rootCaKeyPair.getPrivate(),
        rootCaDn
    );

    childX509Certificate = new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(childCertificateHolder);

    when(
        signedCertificateGenerator
            .getSignedByIssuer(childCertificateKeyPair, inputParameters, rootCaX509Certificate, rootCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);
  }

  private KeyPair setupKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
    return fakeKeyPairGenerator.generate();
  }
}
