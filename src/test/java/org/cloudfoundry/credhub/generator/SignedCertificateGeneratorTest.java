package org.cloudfoundry.credhub.generator;

import org.cloudfoundry.credhub.config.BouncyCastleProviderConfiguration;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters;
import org.cloudfoundry.credhub.util.CertificateReader;
import org.cloudfoundry.credhub.util.PrivateKeyReader;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

import static org.cloudfoundry.credhub.helper.TestHelper.getBouncyCastleProvider;
import static org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters.CODE_SIGNING;
import static org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters.DIGITAL_SIGNATURE;
import static org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters.KEY_ENCIPHERMENT;
import static org.cloudfoundry.credhub.request.CertificateGenerationRequestParameters.SERVER_AUTH;
import static org.cloudfoundry.credhub.util.CertificateStringConstants.CERTSTRAP_GENERATED_CA_CERTIFICATE;
import static org.cloudfoundry.credhub.util.CertificateStringConstants.CERTSTRAP_GENERATED_CA_PRIVATE_KEY;
import static org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = BouncyCastleProviderConfiguration.class)
public class SignedCertificateGeneratorTest {

  private SignedCertificateGenerator subject;
  private X500Principal issuerDn;
  private KeyPair issuerKey;
  private KeyPair generatedCertificateKeyPair;
  private CertificateGenerationParameters certificateGenerationParameters;
  private KeyPairGenerator generator;
  private RandomSerialNumberGenerator serialNumberGenerator;
  private DateTimeProvider timeProvider;
  private Calendar now;
  private Calendar later;
  private CertificateCredentialValue ca;
  private final int expectedDurationInDays = 10;
  private final String caName = "CN=ca DN,O=credhub";
  private final String expectedCertificateCommonName = "my cert name";
  private byte[] expectedSubjectKeyIdentifier;
  private final String[] alternateNames = {"alt1", "alt2"};
  private final String[] keyUsage = {DIGITAL_SIGNATURE, KEY_ENCIPHERMENT};
  private final String[] extendedKeyUsage = {SERVER_AUTH, CODE_SIGNING};

  @Autowired
  private JcaContentSignerBuilder jcaContentSignerBuilder;

  @Autowired
  private JcaX509CertificateConverter jcaX509CertificateConverter;

  private JcaX509ExtensionUtils jcaX509ExtensionUtils;

  private SubjectKeyIdentifier caSubjectKeyIdentifier;
  private X509Certificate certificateAuthority;
  private X509Certificate certificateAuthorityWithSubjectKeyId;
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
    jcaX509ExtensionUtils = new JcaX509ExtensionUtils();

    generator = KeyPairGenerator
        .getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
    generator.initialize(1024); // doesn't matter for testing
    issuerKey = generator.generateKeyPair();

    issuerDn = new X500Principal(caName);
    generatedCertificateKeyPair = generator.generateKeyPair();
    certificateGenerationParameters = defaultCertificateParameters();

    subject = new SignedCertificateGenerator(timeProvider,
        serialNumberGenerator,
        jcaContentSignerBuilder,
        jcaX509CertificateConverter,
        getBouncyCastleProvider()
    );

    caSubjectKeyIdentifier =
        jcaX509ExtensionUtils.createSubjectKeyIdentifier(issuerKey.getPublic());

    caSerialNumber = BigInteger.valueOf(42l);
    JcaX509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
        issuerDn,
        caSerialNumber,
        Date.from(now.toInstant()),
        Date.from(later.toInstant()),
        issuerDn,
        issuerKey.getPublic()
    );

    certificateAuthority = createCertificateAuthority(x509v3CertificateBuilder);

    x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, caSubjectKeyIdentifier);
    certificateAuthorityWithSubjectKeyId = createCertificateAuthority(x509v3CertificateBuilder);
    expectedSubjectKeyIdentifier = certificateAuthorityWithSubjectKeyId.getExtensionValue(Extension.subjectKeyIdentifier.getId());
  }

  private X509Certificate createCertificateAuthority(X509v3CertificateBuilder x509v3CertificateBuilder) throws OperatorCreationException, CertificateException, IOException {
    X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(jcaContentSignerBuilder.build(issuerKey.getPrivate()));
    X509Certificate x509CertificateAuthority = jcaX509CertificateConverter.getCertificate(certificateHolder);
    return x509CertificateAuthority;
  }

  @Test
  public void getSelfSigned_generatesACertificateWithTheRightValues() throws Exception {
    X509Certificate generatedCertificate = subject.getSelfSigned(generatedCertificateKeyPair, certificateGenerationParameters);

    assertThat(generatedCertificate.getIssuerDN().getName(), containsString("CN=my cert name"));
    assertThat(generatedCertificate.getSubjectDN().toString(), containsString("CN=my cert name"));
    generatedCertificate.verify(generatedCertificateKeyPair.getPublic());

    byte[] authorityKeyIdDer = generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));
    byte[] authorityKeyId = authorityKeyIdentifier.getKeyIdentifier();

    expectedSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(generatedCertificateKeyPair.getPublic()).getKeyIdentifier();

    assertThat(authorityKeyId, equalTo(expectedSubjectKeyIdentifier));
    assertThat(generatedCertificate.getSerialNumber(), equalTo(BigInteger.valueOf(1337)));
    assertThat(authorityKeyIdentifier.getAuthorityCertSerialNumber(), equalTo(BigInteger.valueOf(1337)));
  }

  @Test
  public void getSignedByIssuer_generatesACertificateWithTheRightValues() throws Exception {
    X509Certificate generatedCertificate = subject
        .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
            certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

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
        subject.getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, certificateAuthority, issuerKey.getPrivate());

    assertThat(generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId()), nullValue());
  }

  @Test
  public void getSignedByIssuer_withSubjectKeyIdentifier_setsAuthorityKeyIdentifier() throws Exception {
    when(serialNumberGenerator.generate())
        .thenReturn(BigInteger.valueOf(1337))
        .thenReturn(BigInteger.valueOf(666));

    X509Certificate generatedCertificate =
        subject.getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());

    byte[] authorityKeyIdDer = generatedCertificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
    AuthorityKeyIdentifier authorityKeyIdentifier =
        AuthorityKeyIdentifier.getInstance(parseExtensionValue(authorityKeyIdDer));

    assertThat(authorityKeyIdentifier.getKeyIdentifier(), equalTo(caSubjectKeyIdentifier.getKeyIdentifier()));
    assertThat(authorityKeyIdentifier.getAuthorityCertSerialNumber(), equalTo(caSerialNumber));
    String certIssuerName = authorityKeyIdentifier.getAuthorityCertIssuer().getNames()[0].getName().toString();
    assertThat(certIssuerName, containsString("CN=ca DN"));
    assertThat(certIssuerName, containsString("O=credhub"));
  }

  @Test
  public void getSignedByIssuer_setsSubjectKeyIdentifier() throws Exception {
    X509Certificate generatedCertificate = subject
        .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters,
            certificateAuthorityWithSubjectKeyId, issuerKey.getPrivate());
    expectedSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(generatedCertificateKeyPair.getPublic()).getKeyIdentifier();
    byte[] actual = generatedCertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
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

    byte[] actualSubjectAlternativeName = generatedCertificate.getExtensionValue(Extension.subjectAlternativeName.getId());
    byte[] expectedAlternativeName = getExpectedAlternativeNames();
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
    byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.keyUsage.getId());

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
    byte[] actualKeyUsage = generatedCertificate.getExtensionValue(Extension.extendedKeyUsage.getId());

    assertThat(Arrays.copyOfRange(actualKeyUsage, 2, actualKeyUsage.length),
        equalTo(certificateGenerationParameters.getExtendedKeyUsage().getEncoded()));
  }

  @Test
  public void getSignedByIssuer_preservesIssuerBytes() throws Exception {
    X509Certificate caCertificate = CertificateReader
        .getCertificate(CERTSTRAP_GENERATED_CA_CERTIFICATE);
    PrivateKey caPrivateKey = PrivateKeyReader.getPrivateKey(CERTSTRAP_GENERATED_CA_PRIVATE_KEY);
    X509Certificate generatedCertificate = subject
        .getSignedByIssuer(generatedCertificateKeyPair, certificateGenerationParameters, caCertificate, caPrivateKey);

    assertThat(generatedCertificate.getIssuerX500Principal().getEncoded(), equalTo(caCertificate.getSubjectX500Principal().getEncoded()));
  }

  private byte[] getExpectedAlternativeNames() throws IOException {
    return new GeneralNamesBuilder()
        .addName(new GeneralName(GeneralName.dNSName, alternateNames[0]))
        .addName(new GeneralName(GeneralName.dNSName, alternateNames[1])).build().getEncoded();
  }

  private CertificateGenerationParameters defaultCertificateParameters() {
    return new CertificateGenerationParameters(
        new CertificateGenerationRequestParameters()
            .setDuration(expectedDurationInDays)
            .setCommonName(expectedCertificateCommonName)
            .setIsCa(true)
    );
  }

  private CertificateGenerationParameters parametersContainsExtensions() {
    return new CertificateGenerationParameters(
        new CertificateGenerationRequestParameters()
            .setDuration(expectedDurationInDays)
            .setCommonName(expectedCertificateCommonName)
            .setAlternativeNames(alternateNames)
            .setKeyUsage(keyUsage)
            .setExtendedKeyUsage(extendedKeyUsage)
    );
  }
}
