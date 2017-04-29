package io.pivotal.security.generator;

import io.pivotal.security.config.BouncyCastleProviderConfiguration;
import io.pivotal.security.credential.Certificate;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.request.CertificateGenerationParameters;
import io.pivotal.security.util.CertificateFormatter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import static io.pivotal.security.helper.SpectrumHelper.getBouncyCastleProvider;
import static io.pivotal.security.request.CertificateGenerationParameters.*;
import static org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = BouncyCastleProviderConfiguration.class)
public class SignedCertificateGeneratorTest {

  private SignedCertificateGenerator subject;
  private X500Name issuerDn;
  private KeyPair issuerKey;
  private KeyPair generatedCertificateKeyPair;
  private CertificateParameters certificateParameters;
  private KeyPairGenerator generator;
  private X509ExtensionUtils x509ExtensionUtils;
  private RandomSerialNumberGenerator serialNumberGenerator;
  private DateTimeProvider timeProvider;
  private Calendar now;
  private Calendar later;
  private Certificate ca;
  private final int expectedDurationInDays = 10;
  private final String caName = "CN=ca DN,O=credhub";
  private final String expectedCertificateCommonName = "my cert name";
  private final byte[] expectedSubjectKeyIdentifier = "expected subject key identifier".getBytes();
  private final String[] alternateNames = {"alt1", "alt2"};
  private final String[] keyUsage = {DIGITAL_SIGNATURE, KEY_ENCIPHERMENT};
  private final String[] extendedKeyUsage = {SERVER_AUTH, CODE_SIGNING};

  @Autowired
  private JcaContentSignerBuilder jcaContentSignerBuilder;

  @Autowired
  private JcaX509CertificateConverter jcaX509CertificateConverter;
  private SubjectKeyIdentifier caSubjectKeyIdentifier;
  private Certificate certificateAuthority;
  private Certificate certificateAuthorityWithSubjectKeyId;
  private BigInteger caSerialNumber;

  @Before
  public void beforeEach() throws Exception {
    timeProvider = mock(DateTimeProvider.class);
    now = Calendar.getInstance();
    now.setTimeInMillis(1493066824);
    later = (Calendar) now.clone();
    later.add(Calendar.DAY_OF_YEAR, expectedDurationInDays);
    when(timeProvider.getNow()).thenReturn(now);
    serialNumberGenerator = mock(RandomSerialNumberGenerator.class);
    when(serialNumberGenerator.generate()).thenReturn(BigInteger.valueOf(1337));
    x509ExtensionUtils = mock(X509ExtensionUtils.class);
    when(x509ExtensionUtils.createSubjectKeyIdentifier(any())).thenReturn(new SubjectKeyIdentifier(expectedSubjectKeyIdentifier));

    generator = KeyPairGenerator
        .getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    generator.initialize(1024); // doesn't matter for testing

    issuerDn = new X500Name(caName);
    issuerKey = generator.generateKeyPair();
    generatedCertificateKeyPair = generator.generateKeyPair();
    certificateParameters = defaultCertificateParameters();

    subject = new SignedCertificateGenerator(timeProvider,
        serialNumberGenerator,
        x509ExtensionUtils,
        jcaContentSignerBuilder,
        jcaX509CertificateConverter,
        getBouncyCastleProvider()
    );

    caSubjectKeyIdentifier =
        x509ExtensionUtils.createSubjectKeyIdentifier(
            SubjectPublicKeyInfo.getInstance(issuerKey.getPublic().getEncoded())
        );

    caSerialNumber = BigInteger.valueOf(42l);
    X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(
        issuerDn,
        caSerialNumber,
        Date.from(now.toInstant()),
        Date.from(later.toInstant()),
        issuerDn,
        SubjectPublicKeyInfo.getInstance(issuerKey.getPublic().getEncoded())
    );

    certificateAuthority = createCertificateAuthority(x509v3CertificateBuilder);

    x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, caSubjectKeyIdentifier);
    certificateAuthorityWithSubjectKeyId = createCertificateAuthority(x509v3CertificateBuilder);
  }

  private Certificate createCertificateAuthority(X509v3CertificateBuilder x509v3CertificateBuilder) throws OperatorCreationException, CertificateException, IOException {
    X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(jcaContentSignerBuilder.build(issuerKey.getPrivate()));
    X509Certificate x509CertificateAuthority = jcaX509CertificateConverter.getCertificate(certificateHolder);

    String caPem = CertificateFormatter.pemOf(x509CertificateAuthority);
    String caPrivatePem = CertificateFormatter.pemOf(issuerKey.getPrivate());
    return new Certificate("", caPem, caPrivatePem, caName);
  }

  @Test
  public void getSelfSigned_generatesACertificateWithTheRightValues() throws Exception {
    X509Certificate generatedCertificate = subject.getSelfSigned(generatedCertificateKeyPair, certificateParameters);

    assertThat(generatedCertificate.getIssuerDN().getName(), containsString("CN=my cert name"));
    assertThat(generatedCertificate.getSubjectDN().toString(), containsString("CN=my cert name"));
    generatedCertificate.verify(generatedCertificateKeyPair.getPublic());

    byte[] authorityKeyIdDer = generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));
    byte[] authorityKeyId = authorityKeyIdentifier.getKeyIdentifier();

    assertThat(authorityKeyId, equalTo(expectedSubjectKeyIdentifier));
    assertThat(generatedCertificate.getSerialNumber(), equalTo(BigInteger.valueOf(1337)));
    assertThat(authorityKeyIdentifier.getAuthorityCertSerialNumber(), equalTo(BigInteger.valueOf(1337)));
  }

  @Test
  public void getSignedByIssuer_generatesACertificateWithTheRightValues() throws Exception {
    X509Certificate generatedCertificate = setupGetSignedByIssuer();

    assertThat(generatedCertificate.getIssuerDN().getName(), containsString("CN=ca DN"));
    assertThat(generatedCertificate.getIssuerDN().getName(), containsString("O=credhub"));

    assertThat(generatedCertificate.getSerialNumber(), equalTo(BigInteger.valueOf(1337l)));
    assertThat(generatedCertificate.getNotBefore().toString(), equalTo(Date.from(now.toInstant()).toString()));
    assertThat(generatedCertificate.getNotAfter().toString(), equalTo(Date.from(later.toInstant()).toString()));
    assertThat(generatedCertificate.getSubjectDN().toString(), containsString("CN=my cert name"));
    assertThat(generatedCertificate.getPublicKey(), equalTo(generatedCertificateKeyPair.getPublic()));
    assertThat(generatedCertificate.getSigAlgName(), equalTo("SHA256WITHRSA"));
    generatedCertificate.verify(issuerKey.getPublic());

    byte[] isCaExtension = generatedCertificate.getExtensionValue(Extension.basicConstraints.getId());
    assertThat(Arrays.copyOfRange(isCaExtension, 2, isCaExtension.length),
        equalTo(new BasicConstraints(true).getEncoded()));
  }

  @Test
  public void getSignedByIssuer_withoutSubjectKeyIdentifier_doesNotSetAuthorityKeyIdentifier() throws Exception {
    X509Certificate generatedCertificate =
        subject.getSignedByIssuer(generatedCertificateKeyPair, certificateParameters, certificateAuthority);

    assertThat(generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId()), nullValue());
  }

  @Test
  public void getSignedByIssuer_withSubjectKeyIdentifier_setsAuthorityKeyIdentifier() throws Exception {
    when(serialNumberGenerator.generate())
        .thenReturn(BigInteger.valueOf(1337))
        .thenReturn(BigInteger.valueOf(666));

    X509Certificate generatedCertificate =
        subject.getSignedByIssuer(generatedCertificateKeyPair, certificateParameters, certificateAuthorityWithSubjectKeyId);

    byte[] authorityKeyIdDer = generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    AuthorityKeyIdentifier authorityKeyIdentifier =
        AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));

    assertThat(authorityKeyIdentifier.getKeyIdentifier(), equalTo(caSubjectKeyIdentifier.getKeyIdentifier()));
    assertThat(authorityKeyIdentifier.getAuthorityCertSerialNumber(), equalTo(caSerialNumber));
    assertThat(authorityKeyIdentifier.getAuthorityCertIssuer().getNames()[0].getName().toString(), equalTo(caName));
  }

  @Test
  public void getSignedByIssuer_setsSubjectKeyIdentifier() throws Exception {
    X509Certificate generatedCertificate = setupGetSignedByIssuer();

    byte[] actual = generatedCertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    // four bit type field is added at the beginning as per RFC 5280
    assertThat(Arrays.copyOfRange(actual, 4, actual.length), equalTo(expectedSubjectKeyIdentifier));
  }

  @Test
  public void getSignedByIssuer_setsAlternativeName_ifPresent() throws Exception {
    X509Certificate generatedCertificate = setupGetSignedByIssuer();

    assertThat(generatedCertificate.getExtensionValue(Extension.subjectAlternativeName.getId()), nullValue());

    certificateParameters = parametersContainsExtensions();
    generatedCertificate = setupGetSignedByIssuer();

    byte[] actualSubjectAlternativeName = generatedCertificate.getExtensionValue(Extension.subjectAlternativeName.getId());
    byte[] expectedAlternativeName = getExpectedAlternativeNames();
    assertThat(Arrays.copyOfRange(actualSubjectAlternativeName, 2, actualSubjectAlternativeName.length),
        equalTo(expectedAlternativeName));
  }

  @Test
  public void getSignedByIssuer_setsKeyUsage_ifPresent() throws Exception {
    X509Certificate generatedCertificate = setupGetSignedByIssuer();

    assertThat(generatedCertificate.getExtensionValue(Extension.keyUsage.getId()), nullValue());

    certificateParameters = parametersContainsExtensions();

    generatedCertificate = setupGetSignedByIssuer();
    byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.keyUsage.getId());

    assertThat(Arrays.copyOfRange(actualKeyUsage, 5, actualKeyUsage.length),
        equalTo(certificateParameters.getKeyUsage().getBytes()));
  }

  @Test
  public void getSignedByIssuer_setsExtendedKeyUsage_ifPresent() throws Exception {
    X509Certificate generatedCertificate = setupGetSignedByIssuer();

    assertThat(generatedCertificate.getExtensionValue(Extension.keyUsage.getId()), nullValue());

    certificateParameters = parametersContainsExtensions();

    generatedCertificate = setupGetSignedByIssuer();
    byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.extendedKeyUsage.getId());

    assertThat(Arrays.copyOfRange(actualKeyUsage, 2, actualKeyUsage.length),
        equalTo(certificateParameters.getExtendedKeyUsage().getEncoded()));
  }

  private X509Certificate setupGetSignedByIssuer() throws Exception {
    return subject.getSignedByIssuer(generatedCertificateKeyPair, certificateParameters, certificateAuthority);
  }

  private byte[] getExpectedAlternativeNames() throws IOException {
    return new GeneralNamesBuilder()
        .addName(new GeneralName(GeneralName.dNSName, alternateNames[0]))
        .addName(new GeneralName(GeneralName.dNSName, alternateNames[1])).build().getEncoded();
  }

  private CertificateParameters defaultCertificateParameters() {
    return new CertificateParameters(
        new CertificateGenerationParameters()
            .setDuration(expectedDurationInDays)
            .setCommonName(expectedCertificateCommonName)
            .setIsCa(true)
    );
  }

  private CertificateParameters parametersContainsExtensions() {
    return new CertificateParameters(
        new CertificateGenerationParameters()
            .setDuration(expectedDurationInDays)
            .setCommonName(expectedCertificateCommonName)
            .setAlternativeNames(alternateNames)
            .setKeyUsage(keyUsage)
            .setExtendedKeyUsage(extendedKeyUsage)
    );
  }
}
