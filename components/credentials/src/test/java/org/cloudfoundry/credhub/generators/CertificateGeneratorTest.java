package org.cloudfoundry.credhub.generators;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.TestHelper;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters;
import org.cloudfoundry.credhub.services.CertificateAuthorityService;
import org.cloudfoundry.credhub.services.DefaultCertificateAuthorityService;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.CertificateFormatter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.assertj.core.api.Assertions.fail;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CertificateGeneratorTest {

  private CertificateGenerator subject;

  private RsaKeyPairGenerator keyGenerator;
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

  @Before
  public void beforeEach() throws Exception {
    TestHelper.getBouncyCastleFipsProvider();
    keyGenerator = mock(RsaKeyPairGenerator.class);
    signedCertificateGenerator = mock(SignedCertificateGenerator.class);
    certificateAuthorityService = mock(DefaultCertificateAuthorityService.class);

    subject = new CertificateGenerator(
      keyGenerator,
      signedCertificateGenerator,
      certificateAuthorityService,
      0,
      0
    );


    fakeKeyPairGenerator = new FakeKeyPairGenerator();

    rootCaDn = new X500Name("O=foo,ST=bar,C=root");
    signeeDn = new X500Name("O=foo,ST=bar,C=mars");
    rootCaKeyPair = fakeKeyPairGenerator.generate();
    final X509CertificateHolder caX509CertHolder = makeCert(rootCaKeyPair, rootCaKeyPair.getPrivate(),
      rootCaDn, rootCaDn, true);
    rootCaX509Certificate = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).getCertificate(caX509CertHolder);
    rootCa = new CertificateCredentialValue(
            CertificateFormatter.pemOf(rootCaX509Certificate),
            CertificateFormatter.pemOf(rootCaKeyPair.getPrivate()),
            true,
            true,
            false,
            false,
            Instant.now());

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

    final CertificateCredentialValue certificateSignedByRoot = subject.generateCredential(inputParameters);

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
    final CertificateGenerationParameters params = new CertificateGenerationParameters(generationParameters);

    when(
      signedCertificateGenerator
        .getSignedByIssuer(childCertificateKeyPair, params, rootCaX509Certificate, rootCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);

    final CertificateCredentialValue certificate = subject.generateCredential(params);

    assertThat(certificate, notNullValue());
    verify(keyGenerator, times(1)).generateKeyPair(4096);
  }

  @Test
  public void whenCAExists_andItIsAIntermediateCA_aValidChildCertificateIsGenerated()
    throws Exception {
    final KeyPair childCertificateKeyPair = setupKeyPair();

    final X500Name intermediateCaDn = new X500Name("O=foo,ST=bar,C=intermediate");
    final KeyPair intermediateCaKeyPair = fakeKeyPairGenerator.generate();
    final X509CertificateHolder intermediateCaCertificateHolder = makeCert(intermediateCaKeyPair,
      rootCaKeyPair.getPrivate(), rootCaDn, intermediateCaDn, true);
    final X509Certificate intermediateX509Certificate = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
      .getCertificate(intermediateCaCertificateHolder);
    final CertificateCredentialValue intermediateCa = new CertificateCredentialValue(
      null,
      CertificateFormatter.pemOf(intermediateX509Certificate),
      CertificateFormatter.pemOf(intermediateCaKeyPair.getPrivate()),
      null,
      true,
      false,
      false,
      false);
    when(certificateAuthorityService.findActiveVersion("/my-ca-name")).thenReturn(intermediateCa);

    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair);

    final X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
      childCertificateKeyPair,
      intermediateCaKeyPair.getPrivate(),
      intermediateCaDn
    );

    childX509Certificate = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
      .getCertificate(childCertificateHolder);

    when(
      signedCertificateGenerator
        .getSignedByIssuer(childCertificateKeyPair, inputParameters, intermediateX509Certificate, intermediateCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);


    final CertificateCredentialValue certificateSignedByIntermediate = subject.generateCredential(inputParameters);

    assertThat(certificateSignedByIntermediate.getCa(),
      equalTo(intermediateCa.getCertificate()));

    assertThat(certificateSignedByIntermediate.getPrivateKey(),
      equalTo(CertificateFormatter.pemOf(childCertificateKeyPair.getPrivate())));

    assertThat(certificateSignedByIntermediate.getCertificate(),
      equalTo(CertificateFormatter.pemOf(childX509Certificate)));

    verify(keyGenerator, times(1)).generateKeyPair(2048);
  }

  @Test
  public void whenCAExists_andHasATransitionalVersion_aValidChildCertificateIsGenerated() throws Exception {
    final KeyPair childCertificateKeyPair = setupKeyPair();
    setupMocksForRootCA(childCertificateKeyPair);

    KeyPair transitionalCaKeyPair = fakeKeyPairGenerator.generate();
    final X509CertificateHolder caX509CertHolder = makeCert(transitionalCaKeyPair, transitionalCaKeyPair.getPrivate(),
      rootCaDn, rootCaDn, true);
    X509Certificate transitionalCaX509Certificate = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).getCertificate(caX509CertHolder);
    CertificateCredentialValue transitionalCa = new CertificateCredentialValue(
      null,
      CertificateFormatter.pemOf(transitionalCaX509Certificate),
      CertificateFormatter.pemOf(transitionalCaKeyPair.getPrivate()),
      null,
      true,
      true,
      false,
      true);

    generationParameters.setKeyLength(4096);
    final CertificateGenerationParameters params = new CertificateGenerationParameters(generationParameters);

    when(
      signedCertificateGenerator
        .getSignedByIssuer(childCertificateKeyPair, params, rootCaX509Certificate, rootCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);

    when(certificateAuthorityService.findTransitionalVersion("/my-ca-name")).thenReturn(transitionalCa);

    final CertificateCredentialValue certificateWithTrustedCa = subject.generateCredential(inputParameters);

    assertThat(certificateWithTrustedCa.getCa(),
      equalTo(rootCa.getCertificate()));

    assertThat(certificateWithTrustedCa.getTrustedCa(),
      equalTo(transitionalCa.getCertificate()));
  }

  @Test
  public void whenCAHasATransitionalVersionAsLatest_andAllowTransitionalParentToSignIsTrue_childCertificateIsSignedByTheTransitionalVersion() throws Exception {
    final KeyPair childCertificateKeyPair = setupKeyPair();
    KeyPair transitionalCaKeyPair = fakeKeyPairGenerator.generate();

    final X509CertificateHolder caX509CertHolder = makeCert(transitionalCaKeyPair, transitionalCaKeyPair.getPrivate(),
            rootCaDn, rootCaDn, true);
    X509Certificate transitionalCaX509Certificate = new JcaX509CertificateConverter()
            .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME).getCertificate(caX509CertHolder);
    CertificateCredentialValue transitionalCa = new CertificateCredentialValue(
            CertificateFormatter.pemOf(transitionalCaX509Certificate),
            CertificateFormatter.pemOf(transitionalCaKeyPair.getPrivate()),
            true,
            true,
            false,
            true,
            Instant.now());

    when(certificateAuthorityService.findActiveVersion("/my-ca-name")).thenReturn(rootCa);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair);

    final X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
            childCertificateKeyPair,
            transitionalCaKeyPair.getPrivate(),
            rootCaDn
    );

    childX509Certificate = new JcaX509CertificateConverter()
            .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
            .getCertificate(childCertificateHolder);

    inputParameters.setAllowTransitionalParentToSign(true);
    when(signedCertificateGenerator
            .getSignedByIssuer(
                    childCertificateKeyPair,
                    inputParameters,
                    transitionalCaX509Certificate,
                    transitionalCaKeyPair.getPrivate()
            )
    ).thenReturn(childX509Certificate);

    when(certificateAuthorityService.findTransitionalVersion("/my-ca-name")).thenReturn(transitionalCa);

    final CertificateCredentialValue certificateWithTrustedCa = subject.generateCredential(inputParameters);

    assertThat(certificateWithTrustedCa.getCa(),
            equalTo(transitionalCa.getCertificate()));

    assertThat(certificateWithTrustedCa.getTrustedCa(),
            equalTo(rootCa.getCertificate()));
  }

  @Test
  public void whenSelfSignIsTrue_itGeneratesAValidSelfSignedCertificate() throws Exception {
    final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
      .getCertificate(generateX509SelfSignedCert());

    generationParameters.setCaName(null);
    generationParameters.setSelfSigned(true);
    inputParameters = new CertificateGenerationParameters(generationParameters);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);
    when(signedCertificateGenerator.getSelfSigned(rootCaKeyPair, inputParameters))
      .thenReturn(certificate);

    final CertificateCredentialValue certificateCredential = subject.generateCredential(inputParameters);
    assertThat(certificateCredential.getPrivateKey(),
      equalTo(CertificateFormatter.pemOf(rootCaKeyPair.getPrivate())));
    assertThat(certificateCredential.getCertificate(),
      equalTo(CertificateFormatter.pemOf(certificate)));
    assertThat(certificateCredential.getCa(), equalTo(CertificateFormatter.pemOf(certificate)));
    verify(signedCertificateGenerator, times(1)).getSelfSigned(rootCaKeyPair, inputParameters);
    assertThat(certificateCredential.getDurationOverridden(),
            equalTo(false));
  }

  @Test
  public void whenTheCADoesNotHaveAPrivateKey_itThrowsAnException() throws Exception {
    final CertificateGenerationRequestParameters parameters = new CertificateGenerationRequestParameters();
    parameters.setCaName("/ca-without-private-key");
    parameters.setKeyLength(2048);
    parameters.setSelfSigned(false);

    final CertificateCredentialValue caWithoutPrivateKey = mock(CertificateCredentialValue.class);
    when(certificateAuthorityService.findActiveVersion("/ca-without-private-key"))
      .thenReturn(caWithoutPrivateKey);

    when(caWithoutPrivateKey.getPrivateKey()).thenReturn(null);

    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);

    try {
      subject.generateCredential(new CertificateGenerationParameters(parameters));
      fail("Should throw exception");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.CA_MISSING_PRIVATE_KEY));
    }
  }

  @Test
  public void whenSelfSignIsTrueAndItIsCA_itGeneratesAValidSelfSignedCertificateUsingTheCaMinimumDuration() throws Exception {
    final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
            .getCertificate(generateX509SelfSignedCert());
    final CertificateGenerationParameters expectedParameters = setupMinimumDuration(3650, 0, 365, true, true, 3650);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);
    when(signedCertificateGenerator.getSelfSigned(rootCaKeyPair, expectedParameters))
      .thenReturn(certificate);

    final CertificateCredentialValue certificateCA = subject.generateCredential(inputParameters);

    verify(signedCertificateGenerator, times(1)).getSelfSigned(rootCaKeyPair, expectedParameters);
    assertThat(certificateCA.getDurationOverridden(),
            equalTo(true));
  }

  @Test
  public void whenSelfSignIsFalseAndItIsCA_itGeneratesAValidCertificateUsingTheCaMinimumDuration() throws Exception {
    final CertificateGenerationParameters expectedParameters = setupMinimumDuration(3650, 0, 365, true, false, 3650);
    final KeyPair childCertificateKeyPair = setupKeyPair();
    setupMocksForRootCA(childCertificateKeyPair, expectedParameters);

    final CertificateCredentialValue certificateCA = subject.generateCredential(inputParameters);

    verify(signedCertificateGenerator, times(1)).
      getSignedByIssuer(childCertificateKeyPair, expectedParameters, rootCaX509Certificate, rootCaKeyPair.getPrivate());
    assertThat(certificateCA.getDurationOverridden(),
            equalTo(true));
  }

  @Test
  public void whenSelfSignIsTrueAndNotCA_itGeneratesAValidSelfSignedCertificateUsingTheLeafMinimumDuration() throws Exception {
    final X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
            .getCertificate(generateX509SelfSignedCert());
    final CertificateGenerationParameters expectedParameters = setupMinimumDuration(0, 1460, 365, false, true, 1460);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(rootCaKeyPair);
    when(signedCertificateGenerator.getSelfSigned(rootCaKeyPair, expectedParameters))
            .thenReturn(certificate);

    final CertificateCredentialValue certificateLeaf = subject.generateCredential(inputParameters);

    verify(signedCertificateGenerator, times(1)).getSelfSigned(rootCaKeyPair, expectedParameters);
    assertThat(certificateLeaf.getDurationOverridden(),
            equalTo(true));
  }

  @Test
  public void whenSelfSignIsFalseAndNotCA_itGeneratesAValidCertificateUsingTheLeafMinimumDuration() throws Exception {
    final CertificateGenerationParameters expectedParameters = setupMinimumDuration(0, 1460, 365, false, false, 1460);
    final KeyPair childCertificateKeyPair = setupKeyPair();
    setupMocksForRootCA(childCertificateKeyPair, expectedParameters);

    final CertificateCredentialValue certificateLeaf = subject.generateCredential(inputParameters);

    verify(signedCertificateGenerator, times(1)).
            getSignedByIssuer(childCertificateKeyPair, expectedParameters, rootCaX509Certificate, rootCaKeyPair.getPrivate());
    assertThat(certificateLeaf.getDurationOverridden(),
            equalTo(true));
  }

  @Test
  public void whenRequestedDurationIsGreaterThanMinimumDuration_itGeneratesAValidCertificateUsingTheRequestedDuration() throws Exception {
    final CertificateGenerationParameters expectedParameters = setupMinimumDuration(0, 365, 1460, false, false, 1460);
    final KeyPair childCertificateKeyPair = setupKeyPair();
    setupMocksForRootCA(childCertificateKeyPair, expectedParameters);

    final CertificateCredentialValue certificateLeaf = subject.generateCredential(inputParameters);

    verify(signedCertificateGenerator, times(1)).
            getSignedByIssuer(childCertificateKeyPair, expectedParameters, rootCaX509Certificate, rootCaKeyPair.getPrivate());
    assertThat(certificateLeaf.getDurationOverridden(),
            equalTo(false));
  }

  private X509CertificateHolder generateX509SelfSignedCert() throws Exception {
    return makeCert(rootCaKeyPair, rootCaKeyPair.getPrivate(), rootCaDn, rootCaDn, false);
  }

  private X509CertificateHolder generateChildCertificateSignedByCa(final KeyPair certKeyPair,
                                                                   final PrivateKey caPrivateKey,
                                                                   final X500Name caDn) throws Exception {
    return makeCert(certKeyPair, caPrivateKey, caDn, signeeDn, false);
  }

  private X509CertificateHolder makeCert(final KeyPair certKeyPair,
                                         final PrivateKey caPrivateKey,
                                         final X500Name caDn,
                                         final X500Name subjectDn,
                                         final boolean isCa) throws OperatorCreationException, NoSuchAlgorithmException, CertIOException {
    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(certKeyPair.getPublic()
      .getEncoded());
    final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
      .build(caPrivateKey);

    final CurrentTimeProvider currentTimeProvider = new CurrentTimeProvider();

    final Instant now = Instant.from(currentTimeProvider.getInstant());

    final X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
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

  private void setupMocksForRootCA(final KeyPair childCertificateKeyPair) throws Exception {
    setupMocksForRootCA(childCertificateKeyPair, inputParameters);
  }

  private void setupMocksForRootCA(final KeyPair childCertificateKeyPair, final CertificateGenerationParameters params) throws Exception {
    when(certificateAuthorityService.findActiveVersion("/my-ca-name")).thenReturn(rootCa);
    when(keyGenerator.generateKeyPair(anyInt())).thenReturn(childCertificateKeyPair);
    final X509CertificateHolder childCertificateHolder = generateChildCertificateSignedByCa(
      childCertificateKeyPair,
      rootCaKeyPair.getPrivate(),
      rootCaDn
    );

    childX509Certificate = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
      .getCertificate(childCertificateHolder);

    when(
      signedCertificateGenerator
        .getSignedByIssuer(childCertificateKeyPair, params, rootCaX509Certificate, rootCaKeyPair.getPrivate())
    ).thenReturn(childX509Certificate);
  }

  private KeyPair setupKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
    return fakeKeyPairGenerator.generate();
  }

  private CertificateGenerationParameters setupMinimumDuration(final int caMinimumDurationInDays,
                                                               final int leafMinimumDurationInDays,
                                                               final int defaultDuration,
                                                               final boolean ca,
                                                               final boolean selfSigned,
                                                               final int expectedDuration) {
    subject = new CertificateGenerator(
            keyGenerator,
            signedCertificateGenerator,
            certificateAuthorityService,
            caMinimumDurationInDays,
            leafMinimumDurationInDays
    );
    generationParameters.setCa(ca);
    generationParameters.setSelfSigned(selfSigned);
    generationParameters.setDuration(defaultDuration);
    inputParameters = new CertificateGenerationParameters(generationParameters);
    final CertificateGenerationParameters expectedParameters = new CertificateGenerationParameters(generationParameters);
    expectedParameters.setDuration(expectedDuration);
    return expectedParameters;
  }

}
