package org.cloudfoundry.credhub.util;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.Security;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class CertificateReaderTest {
  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void isCa_whenTheCaBasicConstraintIsTrue_returnsTrue() {
    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CA_CERT);

    assertThat(certificateReader.isCa(), equalTo(true));
  }

  @Test
  public void isCa_whenTheCaBasicConstraintIsFalse_returnsFalse() {
    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);

    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void isCa_whenTheCertificateIsX509V3_andDoesNotHaveBasicConstraints_returnsFalse() {
    CertificateReader certificateReader = new CertificateReader(
        CertificateStringConstants.V3_CERT_WITHOUT_BASIC_CONSTRAINTS);

    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void isValid_returnsTrueForValidCert() {
    assertThat(new CertificateReader(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT).isValid(), equalTo(true));
    assertThat(new CertificateReader(CertificateStringConstants.V3_CERT_WITHOUT_BASIC_CONSTRAINTS).isValid(), equalTo(true));
    assertThat(new CertificateReader(CertificateStringConstants.SELF_SIGNED_CA_CERT).isValid(), equalTo(true));
    assertThat(new CertificateReader(CertificateStringConstants.BIG_TEST_CERT).isValid(), equalTo(true));
  }

  @Test
  public void isValid_returnsFalseForInvalidCert() {
    assertThat(new CertificateReader("penguin").isValid(), equalTo(false));
    assertThat(new CertificateReader("").isValid(), equalTo(false));
  }

  @Test
  public void givenASelfSignedCertificate_setsCertificateFieldsCorrectly() {
    final String distinguishedName =
        "O=test-org, ST=Jupiter, C=MilkyWay, CN=test-common-name, OU=test-org-unit, L=Europa";
    final GeneralNames generalNames = new GeneralNames(
        new GeneralName(GeneralName.dNSName, "SolarSystem"));

    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.BIG_TEST_CERT);

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
    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);

    assertThat(certificateReader.getSubjectName().toString(), equalTo(
        "CN=test.example.com, OU=app:b67446e5-b2b0-4648-a0d0-772d3d399dcb, L=exampletown")
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
    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.MISLEADING_CERT);

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
    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CA_CERT);

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
        "O=test-org, ST=Jupiter, C=MilkyWay, CN=test-common-name, OU=test-org-unit, L=Europa";
    final GeneralNames generalNames = new GeneralNames(
        new GeneralName(GeneralName.dNSName, "SolarSystem"));

    CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.BIG_TEST_CERT);

    assertThat(certificateReader.getAlternativeNames(), equalTo(generalNames));
    assertThat(asList(certificateReader.getExtendedKeyUsage().getUsages()),
        containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
    assertThat(certificateReader.getKeyUsage().hasUsages(KeyUsage.digitalSignature),
        equalTo(true));
    assertThat(certificateReader.getSubjectName().toString(), equalTo(distinguishedName));
  }
}


