package org.cloudfoundry.credhub.generators;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.credhub.config.BouncyCastleProviderConfiguration;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.cloudfoundry.credhub.utils.PrivateKeyReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
import static org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
import static org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.CODE_SIGNING;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.CRL_SIGN;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.DIGITAL_SIGNATURE;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.KEY_CERT_SIGN;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.KEY_ENCIPHERMENT;
import static org.cloudfoundry.credhub.requests.CertificateGenerationRequestParameters.SERVER_AUTH;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.CERTSTRAP_GENERATED_CA_CERTIFICATE;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.CERTSTRAP_GENERATED_CA_PRIVATE_KEY;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_CA_WITH_DIFFERENT_SKID;
import static org.cloudfoundry.credhub.utils.TestConstants.TEST_KEY_WITH_DIFFERENT_SKID;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = BouncyCastleProviderConfiguration.class)
public class SignedCertificateGeneratorTest {

  private final int expectedDurationInDays = 10;
  private final String caName = "CN=ca DN,O=credhub";
  private final String expectedCertificateCommonName = "my cert name";
  private final String[] alternateNames = {"alt1", "alt2"};
  private final String[] caKeyUsage = {KEY_CERT_SIGN, CRL_SIGN};
  private final String[] keyUsage = {DIGITAL_SIGNATURE, KEY_ENCIPHERMENT};
  private final String[] extendedKeyUsage = {SERVER_AUTH, CODE_SIGNING};
  private SignedCertificateGenerator subject;
  private X500Principal issuerDn;
  private KeyPair issuerKey;
  private KeyPair generatedCertificateKeyPair;
  private CertificateGenerationParameters certificateGenerationParameters;
  private KeyPairGenerator generator;
  private RandomSerialNumberGenerator serialNumberGenerator;
  private CurrentTimeProvider timeProvider;
  private Instant now;
  private Instant later;
  private byte[] expectedSubjectKeyIdentifier;
  private final byte[] expectedKeyUsageCa = new KeyUsage(keyCertSign | cRLSign).getBytes();
  @Autowired
  private JcaContentSignerBuilder jcaContentSignerBuilder;

  @Autowired
  private JcaX509CertificateConverter jcaX509CertificateConverter;

  private JcaX509ExtensionUtils jcaX509ExtensionUtils;

  private SubjectKeyIdentifier caSubjectKeyIdentifier;
  private X509Certificate certificateAuthority;
  private X509Certificate certificateAuthorityWithSubjectKeyId;
  private BigInteger caSerialNumber;

  @BeforeAll
  static public void beforeAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @BeforeEach
  public void beforeEach() throws Exception {
    timeProvider = mock(CurrentTimeProvider.class);
    now = Instant.ofEpochMilli(1493066824);
    later = now.plus(Duration.ofDays(expectedDurationInDays));
    when(timeProvider.getInstant()).thenReturn(now);
    serialNumberGenerator = mock(RandomSerialNumberGenerator.class);
    when(serialNumberGenerator.generate()).thenReturn(BigInteger.valueOf(1337));
    jcaX509ExtensionUtils = new JcaX509ExtensionUtils();

    generator = KeyPairGenerator
      .getInstance("RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
    generator.initialize(2048); // doesn't matter for testing
    issuerKey = generator.generateKeyPair();

    issuerDn = new X500Principal(caName);
    generatedCertificateKeyPair = generator.generateKeyPair();
    certificateGenerationParameters = defaultCertificateParameters();

    subject = new SignedCertificateGenerator(timeProvider,
      serialNumberGenerator,
      jcaContentSignerBuilder,
      jcaX509CertificateConverter
    );

    caSubjectKeyIdentifier =
      jcaX509ExtensionUtils.createSubjectKeyIdentifier(issuerKey.getPublic());

    caSerialNumber = BigInteger.valueOf(42L);
    final JcaX509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
      issuerDn,
      caSerialNumber,
      Date.from(now),
      Date.from(later),
      issuerDn,
      issuerKey.getPublic()
    );

    certificateAuthority = createCertificateAuthority(x509v3CertificateBuilder);

    x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, caSubjectKeyIdentifier);
    certificateAuthorityWithSubjectKeyId = createCertificateAuthority(x509v3CertificateBuilder);
    expectedSubjectKeyIdentifier = certificateAuthorityWithSubjectKeyId.getExtensionValue(Extension.subjectKeyIdentifier.getId());
  }

  private X509Certificate createCertificateAuthority(final X509v3CertificateBuilder x509v3CertificateBuilder) throws OperatorCreationException, CertificateException {
    final X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(jcaContentSignerBuilder.build(issuerKey.getPrivate()));
    final X509Certificate x509CertificateAuthority = jcaX509CertificateConverter.getCertificate(certificateHolder);
    return x509CertificateAuthority;
  }

  @Test
  public void getSelfSigned_generatesACertificateWithTheRightValues() throws Exception {
    final X509Certificate generatedCertificate = subject.getSelfSigned(generatedCertificateKeyPair, certificateGenerationParameters);

    assertThat(generatedCertificate.getIssuerX500Principal().getName(), containsString("CN=my cert name"));
    assertThat(generatedCertificate.getSubjectX500Principal().toString(), containsString("CN=my cert name"));
    generatedCertificate.verify(generatedCertificateKeyPair.getPublic());

    final byte[] authorityKeyIdDer = generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    final AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));
    final byte[] authorityKeyId = authorityKeyIdentifier.getKeyIdentifier();

    expectedSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(generatedCertificateKeyPair.getPublic()).getKeyIdentifier();

    assertThat(authorityKeyId, equalTo(expectedSubjectKeyIdentifier));
    assertThat(generatedCertificate.getSerialNumber(), equalTo(BigInteger.valueOf(1337)));
  }

  @Test
  public void getSignedByIssuer_generatesACertificateWithTheRightValues() throws Exception {
    final X509Certificate generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    assertThat(generatedCertificate.getIssuerX500Principal().getName(), containsString("CN=ca DN"));
    assertThat(generatedCertificate.getIssuerX500Principal().getName(), containsString("O=credhub"));

    assertThat(generatedCertificate.getSerialNumber(), equalTo(BigInteger.valueOf(1337L)));
    assertThat(generatedCertificate.getNotBefore().toString(), equalTo(Date.from(now).toString()));
    assertThat(generatedCertificate.getNotAfter().toString(), equalTo(Date.from(later).toString()));
    assertThat(generatedCertificate.getSubjectX500Principal().toString(), containsString("CN=my cert name"));
    assertThat(generatedCertificate.getPublicKey(), equalTo(generatedCertificateKeyPair.getPublic()));
    assertThat(generatedCertificate.getSigAlgName(), equalTo("SHA256WITHRSA"));
    generatedCertificate.verify(issuerKey.getPublic());

    final byte[] isCaExtension = generatedCertificate.getExtensionValue(Extension.basicConstraints.getId());
    assertThat(Arrays.copyOfRange(isCaExtension, 2, isCaExtension.length),
      equalTo(new BasicConstraints(true).getEncoded()));
  }

  @Test
  public void getSignedByIssuer_withoutSubjectKeyIdentifier_doesNotSetAuthorityKeyIdentifier() throws Exception {
    final X509Certificate generatedCertificate =
      subject.getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, certificateAuthority, issuerKey.getPrivate());

    assertThat(generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId()), nullValue());
  }

  @Test
  public void getSignedByIssuer_withSubjectKeyIdentifier_setsAuthorityKeyIdentifier() throws Exception {
    when(serialNumberGenerator.generate())
      .thenReturn(BigInteger.valueOf(1337))
      .thenReturn(BigInteger.valueOf(666));

    final X509Certificate generatedCertificate =
      subject.getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    final byte[] authorityKeyIdDer = generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    final AuthorityKeyIdentifier authorityKeyIdentifier =
      AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));

    assertThat(authorityKeyIdentifier.getKeyIdentifier(), equalTo(caSubjectKeyIdentifier.getKeyIdentifier()));
  }

  @Test
  public void getSignedByIssuer_withNonGeneratedSubjectKeyIdentifier_setsAuthorityKeyIdentifier() throws Exception {
    final X509Certificate caCertificate = new CertificateReader(TEST_CA_WITH_DIFFERENT_SKID).getCertificate();
    PrivateKey caPrivateKey = PrivateKeyReader.getPrivateKey(TEST_KEY_WITH_DIFFERENT_SKID);

    final X509Certificate generatedCert = subject
            .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, caCertificate, caPrivateKey);

    final byte[] authorityKeyIdDer = generatedCert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    final AuthorityKeyIdentifier authorityKeyIdentifier =
            AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));

    final byte[] subjectKeyIdDer = caCertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(parseExtensionValue(subjectKeyIdDer));

    assertThat(authorityKeyIdentifier.getKeyIdentifier(), equalTo(subjectKeyIdentifier.getKeyIdentifier()));
  }

  @Test
  public void getSignedByIssuer_setsSubjectKeyIdentifier() throws Exception {
    final X509Certificate generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());
    expectedSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(generatedCertificateKeyPair.getPublic()).getKeyIdentifier();
    final byte[] actual = generatedCertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    // four bit type field is added at the beginning as per RFC 5280
    assertThat(Arrays.copyOfRange(actual, 4, actual.length), equalTo(expectedSubjectKeyIdentifier));
  }

  @Test
  public void getSignedByIssuer_setsAlternativeName_ifPresent() throws Exception {
    X509Certificate generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    assertThat(generatedCertificate.getExtensionValue(Extension.subjectAlternativeName.getId()), nullValue());

    certificateGenerationParameters = parametersContainsExtensions();
    generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    final byte[] actualSubjectAlternativeName = generatedCertificate.getExtensionValue(Extension.subjectAlternativeName.getId());
    final byte[] expectedAlternativeName = getExpectedAlternativeNames();
    assertThat(Arrays.copyOfRange(actualSubjectAlternativeName, 2, actualSubjectAlternativeName.length),
      equalTo(expectedAlternativeName));
  }

  @Test
  public void getSignedByIssuer_setsKeyUsage_ifPresent() throws Exception {
    X509Certificate generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    assertThat(generatedCertificate.getExtensionValue(Extension.keyUsage.getId()), nullValue());

    certificateGenerationParameters = parametersContainsExtensions();

    generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());
    final byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.keyUsage.getId());

    assertThat(Arrays.copyOfRange(actualKeyUsage, 5, actualKeyUsage.length),
      equalTo(certificateGenerationParameters.getKeyUsage().getBytes()));
  }

  @Test
  public void getSignedByIssuer_setsExtendedKeyUsage_ifPresent() throws Exception {
    X509Certificate generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    assertThat(generatedCertificate.getExtensionValue(Extension.keyUsage.getId()), nullValue());

    certificateGenerationParameters = parametersContainsExtensions();

    generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
        certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());
    final byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.extendedKeyUsage.getId());

    assertThat(Arrays.copyOfRange(actualKeyUsage, 2, actualKeyUsage.length),
      equalTo(certificateGenerationParameters.getExtendedKeyUsage().getEncoded()));
  }

  @Test
  public void getSignedByIssuer_preservesIssuerBytes() throws Exception {
    final CertificateReader certificateReader = new CertificateReader(CERTSTRAP_GENERATED_CA_CERTIFICATE);
    final X509Certificate caCertificate = certificateReader.getCertificate();
    final PrivateKey caPrivateKey = PrivateKeyReader.getPrivateKey(CERTSTRAP_GENERATED_CA_PRIVATE_KEY);
    final X509Certificate generatedCertificate = subject
      .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, caCertificate, caPrivateKey);

    assertThat(generatedCertificate.getIssuerX500Principal().getEncoded(), equalTo(caCertificate.getSubjectX500Principal().getEncoded()));
  }

  private byte[] getExpectedAlternativeNames() throws IOException {
    return new GeneralNamesBuilder()
      .addName(new GeneralName(GeneralName.dNSName, alternateNames[0]))
      .addName(new GeneralName(GeneralName.dNSName, alternateNames[1])).build().getEncoded();
  }

  private CertificateGenerationParameters defaultCertificateParameters() {

    final CertificateGenerationRequestParameters parameters = new CertificateGenerationRequestParameters();
    parameters.setDuration(expectedDurationInDays);
    parameters.setCommonName(expectedCertificateCommonName);
    parameters.setCa(true);

    return new CertificateGenerationParameters(parameters);
  }
  private CertificateGenerationParameters defaultCertificateParametersWithKeyUsages() {

    final CertificateGenerationRequestParameters parameters = new CertificateGenerationRequestParameters();
    parameters.setDuration(expectedDurationInDays);
    parameters.setCommonName(expectedCertificateCommonName);
    parameters.setKeyUsage(caKeyUsage);
    parameters.setCa(true);

    return new CertificateGenerationParameters(parameters);
  }

  private CertificateGenerationParameters parametersContainsExtensions() {

    final CertificateGenerationRequestParameters parameters = new CertificateGenerationRequestParameters();
    parameters.setDuration(expectedDurationInDays);
    parameters.setCommonName(expectedCertificateCommonName);
    parameters.setAlternativeNames(alternateNames);
    parameters.setKeyUsage(keyUsage);
    parameters.setExtendedKeyUsage(extendedKeyUsage);

    return new CertificateGenerationParameters(parameters);
  }
  private CertificateGenerationParameters parametersContainsExtensionsWithKeyUsages() {

    final CertificateGenerationRequestParameters parameters = new CertificateGenerationRequestParameters();
    parameters.setDuration(expectedDurationInDays);
    parameters.setCommonName(expectedCertificateCommonName);
    parameters.setAlternativeNames(alternateNames);
    parameters.setKeyUsage(keyUsage);
    parameters.setExtendedKeyUsage(extendedKeyUsage);

    return new CertificateGenerationParameters(parameters);
  }

  @Nested
  public class KeyUsageTest {

    private CertificateGenerationParameters certificateGenerationParametersWithKeyUsages;

    @BeforeEach
    public void setUp() {
      certificateGenerationParametersWithKeyUsages = defaultCertificateParametersWithKeyUsages();
    }

    @Test
    public void getSignedByIssuer_setsKeyUsage_ifEnvVarPresent() throws Exception {
      X509Certificate generatedCertificate = subject
              .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParametersWithKeyUsages,
                      certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

      final byte[] generatedKeyUsage = generatedCertificate.getExtensionValue(Extension.keyUsage.getId());
      assertThat(generatedKeyUsage, notNullValue());
      assertThat(Arrays.copyOfRange(generatedKeyUsage, 5, generatedKeyUsage.length), equalTo(expectedKeyUsageCa));

      certificateGenerationParametersWithKeyUsages = parametersContainsExtensionsWithKeyUsages();

      generatedCertificate = subject
              .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParametersWithKeyUsages,
                      certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());
      final byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.keyUsage.getId());

      assertThat(Arrays.copyOfRange(actualKeyUsage, 5, actualKeyUsage.length),
              equalTo(certificateGenerationParametersWithKeyUsages.getKeyUsage().getBytes()));
    }
  }

}
