package org.cloudfoundry.credhub.utils;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.BIG_TEST_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.MISLEADING_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.V3_CERT_WITHOUT_BASIC_CONSTRAINTS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;

public class CertificateReaderTest {
  @BeforeAll
  public static void setUpAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @BeforeEach
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }
  }

  @Test
  public void isCa_whenTheCaBasicConstraintIsTrue_returnsTrue() {
    final CertificateReader certificateReader = new CertificateReader(SELF_SIGNED_CA_CERT);

    assertThat(certificateReader.isCa(), equalTo(true));
  }

  @Test
  public void isCa_whenTheCaBasicConstraintIsFalse_returnsFalse() {
    final CertificateReader certificateReader = new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT);
    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void isCa_whenTheCertificateIsX509V3_andDoesNotHaveBasicConstraints_returnsFalse() {
    final CertificateReader certificateReader = new CertificateReader(
            V3_CERT_WITHOUT_BASIC_CONSTRAINTS);

    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void certificateReader_whenCertificateIsValid_doesNotThrowException() {
    new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT);
    new CertificateReader(V3_CERT_WITHOUT_BASIC_CONSTRAINTS);
    new CertificateReader(SELF_SIGNED_CA_CERT);
    new CertificateReader(BIG_TEST_CERT);
  }

  @Test
  public void certificateReader_whenCertificateIsInvalid_throwsException() {
    assertThatThrownBy(() -> {
      new CertificateReader("penguin");
    }).isInstanceOf(MalformedCertificateException.class);

    assertThatThrownBy(() -> {
      new CertificateReader("");
    }).isInstanceOf(MalformedCertificateException.class);
  }

  @Test
  public void givenASelfSignedCertificate_setsCertificateFieldsCorrectly() {
    final String distinguishedName =
      "L=Europa, OU=test-org-unit, CN=test-common-name, C=MilkyWay, ST=Jupiter, O=test-org";
    final GeneralNames generalNames = new GeneralNames(
      new GeneralName(GeneralName.dNSName, "SolarSystem"));

    final CertificateReader certificateReader = new CertificateReader(BIG_TEST_CERT);

    assertThat(certificateReader.getSubjectName().toString(), equalTo(distinguishedName));
    assertThat(certificateReader.getKeyLength(), equalTo(4096));
    assertThat(certificateReader.getAlternativeNames(), equalTo(generalNames));
    assertThat(asList(certificateReader.getExtendedKeyUsage().getUsages()),
      containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
    assertThat(certificateReader.getKeyUsage().hasUsages(KeyUsage.digitalSignature),
      equalTo(true));
    assertThat(certificateReader.getDurationDays(), equalTo(30));
    assertThat(certificateReader.isSelfSigned(), equalTo(false));
    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void givenASimpleSelfSignedCertificate_setsCertificateFieldsCorrectly() {
    final CertificateReader certificateReader = new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT);

    assertThat(certificateReader.getSubjectName().toString(), equalTo(
      "L=exampletown, OU=app:b67446e5-b2b0-4648-a0d0-772d3d399dcb, CN=test.example.com")
    );
    assertThat(certificateReader.getKeyLength(), equalTo(2048));
    assertThat(certificateReader.getAlternativeNames(), equalTo(null));
    assertThat(certificateReader.getExtendedKeyUsage(), equalTo(null));
    assertThat(certificateReader.getKeyUsage(), equalTo(null));
    assertThat(certificateReader.getDurationDays(), equalTo(3650));
    assertThat(certificateReader.isSelfSigned(), equalTo(true));
    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void givenADeceptiveAndNotSelfSignedCertificate_setsCertificateFieldsCorrectly() {
    final CertificateReader certificateReader = new CertificateReader(MISLEADING_CERT);

    assertThat(certificateReader.getSubjectName().toString(), equalTo("CN=trickster"));
    assertThat(certificateReader.getKeyLength(), equalTo(2048));
    assertThat(certificateReader.getAlternativeNames(), equalTo(null));
    assertThat(certificateReader.getExtendedKeyUsage(), equalTo(null));
    assertThat(certificateReader.getKeyUsage(), equalTo(null));
    assertThat(certificateReader.getDurationDays(), equalTo(365));
    assertThat(certificateReader.isSelfSigned(), equalTo(false));
    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void givenACertificateAuthority_setsCertificateFieldsCorrectly() {
    final CertificateReader certificateReader = new CertificateReader(SELF_SIGNED_CA_CERT);

    assertThat(certificateReader.getSubjectName().toString(), equalTo("CN=foo.com"));
    assertThat(certificateReader.getKeyLength(), equalTo(2048));
    assertThat(certificateReader.getAlternativeNames(), equalTo(null));
    assertThat(certificateReader.getExtendedKeyUsage(), equalTo(null));
    assertThat(certificateReader.getKeyUsage(), equalTo(null));
    assertThat(certificateReader.getDurationDays(), equalTo(365));
    assertThat(certificateReader.isSelfSigned(), equalTo(true));
    assertThat(certificateReader.isCa(), equalTo(true));
  }

  @Test
  public void returnsParametersCorrectly() {
    final String distinguishedName =
      "L=Europa, OU=test-org-unit, CN=test-common-name, C=MilkyWay, ST=Jupiter, O=test-org";
    final GeneralNames generalNames = new GeneralNames(
      new GeneralName(GeneralName.dNSName, "SolarSystem"));

    final CertificateReader certificateReader = new CertificateReader(BIG_TEST_CERT);

    assertThat(certificateReader.getAlternativeNames(), equalTo(generalNames));
    assertThat(asList(certificateReader.getExtendedKeyUsage().getUsages()),
      containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
    assertThat(certificateReader.getKeyUsage().hasUsages(KeyUsage.digitalSignature),
      equalTo(true));
    assertThat(certificateReader.getSubjectName().toString(), equalTo(distinguishedName));
  }

  @Test
  public void regenerationConstructor_preservesDnsSans() throws Exception {
    final GeneralNames expectedSans = new GeneralNames(
      new GeneralName(GeneralName.dNSName, "SolarSystem"));

    final CertificateReader reader = new CertificateReader(BIG_TEST_CERT);
    final CertificateGenerationParameters params = new CertificateGenerationParameters(reader, null);

    assertThat(params.getAlternativeNames(), equalTo(expectedSans));
  }

  @Test
  public void regenerationConstructor_preservesIpAndDnsSans() throws Exception {
    final String certPem = generateSelfSignedCert(
      new GeneralName(GeneralName.iPAddress, "10.0.0.1"),
      new GeneralName(GeneralName.dNSName, "example.com"),
      new GeneralName(GeneralName.iPAddress, "192.168.1.100")
    );

    final GeneralNames expectedSans = new GeneralNamesBuilder()
      .addName(new GeneralName(GeneralName.iPAddress, "10.0.0.1"))
      .addName(new GeneralName(GeneralName.dNSName, "example.com"))
      .addName(new GeneralName(GeneralName.iPAddress, "192.168.1.100"))
      .build();

    final CertificateReader reader = new CertificateReader(certPem);
    final CertificateGenerationParameters params = new CertificateGenerationParameters(reader, null);

    assertThat(params.getAlternativeNames(), equalTo(expectedSans));
  }

  @Test
  public void regenerationConstructor_preservesNullSans() {
    final CertificateReader reader = new CertificateReader(SIMPLE_SELF_SIGNED_TEST_CERT);
    final CertificateGenerationParameters params = new CertificateGenerationParameters(reader, null);

    assertThat(params.getAlternativeNames(), equalTo(null));
  }

  @Test
  public void regenerationConstructor_preservesKeyUsage() throws Exception {
    final KeyUsage expectedKeyUsage = new KeyUsage(KeyUsage.digitalSignature);

    final CertificateReader reader = new CertificateReader(BIG_TEST_CERT);
    final CertificateGenerationParameters params = new CertificateGenerationParameters(reader, null);

    assertThat(params.getKeyUsage(), equalTo(expectedKeyUsage));
  }

  @Test
  public void regenerationConstructor_preservesExtendedKeyUsage() {
    final CertificateReader reader = new CertificateReader(BIG_TEST_CERT);
    final CertificateGenerationParameters params = new CertificateGenerationParameters(reader, null);

    assertThat(asList(params.getExtendedKeyUsage().getUsages()),
      containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
  }

  @Test
  public void regenerationConstructor_allowsKeyUsageOverride() throws Exception {
    final String caCertPem = generateSelfSignedCaCert();
    final CertificateReader reader = new CertificateReader(caCertPem);

    assertThat("CA cert should have no key usage", reader.getKeyUsage(), equalTo(null));

    final CertificateGenerationParameters params = new CertificateGenerationParameters(reader, null);
    final KeyUsage defaultCaKeyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    params.setKeyUsage(defaultCaKeyUsage);

    assertThat(params.getKeyUsage(), equalTo(defaultCaKeyUsage));
  }

  private static String generateSelfSignedCert(final GeneralName... sans) throws Exception {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
      "RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final X500Name subject = new X500Name("CN=test");
    final Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
    final Date notAfter = new Date(System.currentTimeMillis() + 86400000L);

    final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
      subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());

    final GeneralNamesBuilder sanBuilder = new GeneralNamesBuilder();
    for (final GeneralName san : sans) {
      sanBuilder.addName(san);
    }
    certBuilder.addExtension(Extension.subjectAlternativeName, false, sanBuilder.build());

    return signAndEncode(certBuilder, keyPair);
  }

  private static String generateSelfSignedCaCert() throws Exception {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
      "RSA", BouncyCastleFipsProvider.PROVIDER_NAME);
    keyPairGenerator.initialize(2048);
    final KeyPair keyPair = keyPairGenerator.generateKeyPair();

    final X500Name subject = new X500Name("CN=test-ca");
    final Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
    final Date notAfter = new Date(System.currentTimeMillis() + 86400000L);

    final X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
      subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    return signAndEncode(certBuilder, keyPair);
  }

  private static String signAndEncode(final X509v3CertificateBuilder certBuilder, final KeyPair keyPair) throws Exception {
    final var cert = new JcaX509CertificateConverter()
      .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
      .getCertificate(certBuilder.build(
        new JcaContentSignerBuilder("SHA256withRSA")
          .setProvider(BouncyCastleFipsProvider.PROVIDER_NAME)
          .build(keyPair.getPrivate())));

    final StringWriter stringWriter = new StringWriter();
    try (final JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
      pemWriter.writeObject(cert);
    }
    return stringWriter.toString();
  }
}
