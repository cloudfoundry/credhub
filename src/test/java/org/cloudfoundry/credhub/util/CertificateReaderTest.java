package org.cloudfoundry.credhub.util;

import java.security.Security;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.exceptions.MalformedCertificateException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static java.util.Arrays.asList;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(JUnit4.class)
public class CertificateReaderTest {
  @Before
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }
  }

  @Test
  public void isCa_whenTheCaBasicConstraintIsTrue_returnsTrue() {
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CA_CERT);

    assertThat(certificateReader.isCa(), equalTo(true));
  }

  @Test
  public void isCa_whenTheCaBasicConstraintIsFalse_returnsFalse() {
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);
    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void isCa_whenTheCertificateIsX509V3_andDoesNotHaveBasicConstraints_returnsFalse() {
    final CertificateReader certificateReader = new CertificateReader(
      CertificateStringConstants.V3_CERT_WITHOUT_BASIC_CONSTRAINTS);

    assertThat(certificateReader.isCa(), equalTo(false));
  }

  @Test
  public void certificateReader_whenCertificateIsValid_doesNotThrowException() {
    new CertificateReader(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);
    new CertificateReader(CertificateStringConstants.V3_CERT_WITHOUT_BASIC_CONSTRAINTS);
    new CertificateReader(CertificateStringConstants.SELF_SIGNED_CA_CERT);
    new CertificateReader(CertificateStringConstants.BIG_TEST_CERT);
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

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.BIG_TEST_CERT);

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
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);

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
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.MISLEADING_CERT);

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
    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.SELF_SIGNED_CA_CERT);

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

    final CertificateReader certificateReader = new CertificateReader(CertificateStringConstants.BIG_TEST_CERT);

    assertThat(certificateReader.getAlternativeNames(), equalTo(generalNames));
    assertThat(asList(certificateReader.getExtendedKeyUsage().getUsages()),
      containsInAnyOrder(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth));
    assertThat(certificateReader.getKeyUsage().hasUsages(KeyUsage.digitalSignature),
      equalTo(true));
    assertThat(certificateReader.getSubjectName().toString(), equalTo(distinguishedName));
  }
}
