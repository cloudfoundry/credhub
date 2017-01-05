package io.pivotal.security.controller.v1;

import io.pivotal.security.view.ParameterizedValidationException;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class CertificateSecretParametersTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void constructsDNStringWhenAllParamsArePresent() throws Exception {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.setOrganizationUnit("My Organization Unit");
    params.setCommonName("My Common Name");
    params.setLocality("My Locality");

    assertThat(params.getDN().toString(), equalTo("O=My Organization,ST=My State,C=My Country,CN=My Common Name,OU=My Organization Unit,L=My Locality"));
  }

  @Test
  public void constructsDNStringWhenOnlyOneParamIsPresent() throws Exception {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");

    assertThat(params.getDN().toString(), equalTo("C=My Country"));
  }

  @Test
  public void canAddAlternativeNames() throws IOException {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addAlternativeNames("alternative-name-1", "alternative-name-2");

    ASN1Sequence sequence = ASN1Sequence.getInstance(params.getAlternativeNames());
    assertThat(sequence.getObjectAt(0), equalTo(new GeneralName(GeneralName.dNSName, "alternative-name-1")));
    assertThat(sequence.getObjectAt(1), equalTo(new GeneralName(GeneralName.dNSName, "alternative-name-2")));
  }

  @Test
  public void canAddExtendedKeyUsages() throws IOException {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addExtendedKeyUsages("server_auth", "client_auth", "code_signing", "email_protection", "time_stamping");

    ExtendedKeyUsage extendedKeyUsages = ExtendedKeyUsage.getInstance(params.getExtendedKeyUsages());
    assertThat(extendedKeyUsages.getUsages()[0], equalTo(KeyPurposeId.id_kp_serverAuth));
    assertThat(extendedKeyUsages.getUsages()[1], equalTo(KeyPurposeId.id_kp_clientAuth));
    assertThat(extendedKeyUsages.getUsages()[2], equalTo(KeyPurposeId.id_kp_codeSigning));
    assertThat(extendedKeyUsages.getUsages()[3], equalTo(KeyPurposeId.id_kp_emailProtection));
    assertThat(extendedKeyUsages.getUsages()[4], equalTo(KeyPurposeId.id_kp_timeStamping));
  }

  @Test
  public void validatesExtendedKeyUsages() {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    try {
      params.addExtendedKeyUsages("client_auth", "server_off");
      fail();
    } catch (ParameterizedValidationException pve) {
      assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_extended_key_usage"));
      assertThat(pve.getParameters()[0], equalTo("server_off"));
    }
  }

  @Test
  public void canAddKeyUsages() throws IOException {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addKeyUsages("digital_signature", "non_repudiation", "key_encipherment", "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only");

    KeyUsage keyUsages = KeyUsage.getInstance(params.getKeyUsages());
    assertThat(keyUsages.hasUsages(KeyUsage.digitalSignature), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.nonRepudiation), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.keyEncipherment), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.dataEncipherment), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.keyAgreement), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.keyCertSign), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.cRLSign), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.encipherOnly), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.decipherOnly), equalTo(true));

    params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addKeyUsages("digital_signature", "non_repudiation", "decipher_only");

    keyUsages = KeyUsage.getInstance(params.getKeyUsages());
    assertThat(keyUsages.hasUsages(KeyUsage.digitalSignature), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.nonRepudiation), equalTo(true));
    assertThat(keyUsages.hasUsages(KeyUsage.keyEncipherment), equalTo(false));
    assertThat(keyUsages.hasUsages(KeyUsage.dataEncipherment), equalTo(false));
    assertThat(keyUsages.hasUsages(KeyUsage.keyAgreement), equalTo(false));
    assertThat(keyUsages.hasUsages(KeyUsage.keyCertSign), equalTo(false));
    assertThat(keyUsages.hasUsages(KeyUsage.cRLSign), equalTo(false));
    assertThat(keyUsages.hasUsages(KeyUsage.encipherOnly), equalTo(false));
    assertThat(keyUsages.hasUsages(KeyUsage.decipherOnly), equalTo(true));
  }

  @Test
  public void validatesKeyUsages() {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    try {
      params.addKeyUsages("key_agreement", "digital_sinnature");
      fail();
    } catch (ParameterizedValidationException pve) {
      assertThat(pve.getLocalizedMessage(), equalTo("error.invalid_key_usage"));
      assertThat(pve.getParameters()[0], equalTo("digital_sinnature"));
    }
  }

  @Test
  public void durationIs365DaysByDefault() {
    assertThat(new CertificateSecretParameters().getDurationDays(), equalTo(365));
  }

  @Test
  public void canSetDuration() {
    CertificateSecretParameters subject = new CertificateSecretParameters();
    subject.setDurationDays(789);
    assertThat(subject.getDurationDays(), equalTo(789));
  }

  @Test
  public void tooSmallDuration() {
    testDuration(0, false);
  }

  @Test
  public void tooLargeDuration() {
    testDuration(3651, false);
  }

  private void testDuration(int duration, boolean pass) {
    CertificateSecretParameters params = new CertificateSecretParameters()
        .setOrganization("foo")
        .setState("bar")
        .setCountry("baz");

    if (!pass) {
      thrown.expectMessage("error.invalid_duration");
    }

    params.setDurationDays(duration);
    params.validate();
  }

  @Test
  public void failWhenAllAreEmpty() {
    doValidateTest(false, "", "", "", "", "", "");
  }

  @Test
  public void atLeastOneIsNonEmpty() {
    doValidateTest(true, "", "", "", "", "", "a");
    doValidateTest(true, "", "", "", "", "b", "");
    doValidateTest(true, "", "", "", "", "b", "a");
    doValidateTest(true, "", "", "", "c", "", "");
    doValidateTest(true, "", "", "", "c", "", "a");
    doValidateTest(true, "", "", "", "c", "b", "");
    doValidateTest(true, "", "", "", "c", "b", "a");
    doValidateTest(true, "", "", "d", "", "", "");
    doValidateTest(true, "", "", "d", "", "", "a");
    doValidateTest(true, "", "", "d", "", "b", "");
    doValidateTest(true, "", "", "d", "", "b", "a");
    doValidateTest(true, "", "", "d", "c", "", "");
    doValidateTest(true, "", "", "d", "c", "", "a");
    doValidateTest(true, "", "", "d", "c", "b", "");
    doValidateTest(true, "", "", "d", "c", "b", "a");
    doValidateTest(true, "", "e", "", "", "", "");
    doValidateTest(true, "", "e", "", "", "", "a");
    doValidateTest(true, "", "e", "", "", "b", "");
    doValidateTest(true, "", "e", "", "", "b", "a");
    doValidateTest(true, "", "e", "", "c", "", "");
    doValidateTest(true, "", "e", "", "c", "", "a");
    doValidateTest(true, "", "e", "", "c", "b", "");
    doValidateTest(true, "", "e", "", "c", "b", "a");
    doValidateTest(true, "", "e", "d", "", "", "");
    doValidateTest(true, "", "e", "d", "", "", "a");
    doValidateTest(true, "", "e", "d", "", "b", "");
    doValidateTest(true, "", "e", "d", "", "b", "a");
    doValidateTest(true, "", "e", "d", "c", "", "");
    doValidateTest(true, "", "e", "d", "c", "", "a");
    doValidateTest(true, "", "e", "d", "c", "b", "");
    doValidateTest(true, "", "e", "d", "c", "b", "a");
    doValidateTest(true, "f", "", "", "", "", "");
    doValidateTest(true, "f", "", "", "", "", "a");
    doValidateTest(true, "f", "", "", "", "b", "");
    doValidateTest(true, "f", "", "", "", "b", "a");
    doValidateTest(true, "f", "", "", "c", "", "");
    doValidateTest(true, "f", "", "", "c", "", "a");
    doValidateTest(true, "f", "", "", "c", "b", "");
    doValidateTest(true, "f", "", "", "c", "b", "a");
    doValidateTest(true, "f", "", "d", "", "", "");
    doValidateTest(true, "f", "", "d", "", "", "a");
    doValidateTest(true, "f", "", "d", "", "b", "");
    doValidateTest(true, "f", "", "d", "", "b", "a");
    doValidateTest(true, "f", "", "d", "c", "", "");
    doValidateTest(true, "f", "", "d", "c", "", "a");
    doValidateTest(true, "f", "", "d", "c", "b", "");
    doValidateTest(true, "f", "", "d", "c", "b", "a");
    doValidateTest(true, "f", "e", "", "", "", "");
    doValidateTest(true, "f", "e", "", "", "", "a");
    doValidateTest(true, "f", "e", "", "", "b", "");
    doValidateTest(true, "f", "e", "", "", "b", "a");
    doValidateTest(true, "f", "e", "", "c", "", "");
    doValidateTest(true, "f", "e", "", "c", "", "a");
    doValidateTest(true, "f", "e", "", "c", "b", "");
    doValidateTest(true, "f", "e", "", "c", "b", "a");
    doValidateTest(true, "f", "e", "d", "", "", "");
    doValidateTest(true, "f", "e", "d", "", "", "a");
    doValidateTest(true, "f", "e", "d", "", "b", "");
    doValidateTest(true, "f", "e", "d", "", "b", "a");
    doValidateTest(true, "f", "e", "d", "c", "", "");
    doValidateTest(true, "f", "e", "d", "c", "", "a");
    doValidateTest(true, "f", "e", "d", "c", "b", "");
    doValidateTest(true, "f", "e", "d", "c", "b", "a");
  }

  @Test
  public void validKeyLengthsPassValidation() {
    testKeyLength(2048, true);
    testKeyLength(3072, true);
    testKeyLength(4096, true);
  }

  @Test
  public void tooShortKeyLengthFailsValidation() {
    testKeyLength(1024, false);
  }

  @Test
  public void tooLongKeyLengthFailsValidation() {
    testKeyLength(9192, false);
  }

  @Test
  public void invalidKeyLengthFailsValidation() {
    testKeyLength(2222, false);
  }

  private void testKeyLength(int length, boolean pass) {
    CertificateSecretParameters params = new CertificateSecretParameters()
        .setOrganization("foo")
        .setState("bar")
        .setCountry("baz");

    if (!pass) {
      thrown.expectMessage("error.invalid_key_length");
    }

    params.setKeyLength(length);
    params.validate();
  }

  private void doValidateTest(boolean isExpectedValid, String organization, String state, String country, String commonName, String organizationUnit, String locality) {
    CertificateSecretParameters params = new CertificateSecretParameters()
        .setOrganization(organization)
        .setState(state)
        .setCountry(country)
        .setCommonName(commonName)
        .setOrganizationUnit(organizationUnit)
        .setLocality(locality);

    if (!isExpectedValid) {
      thrown.expect(ParameterizedValidationException.class);
      thrown.expectMessage("error.missing_certificate_parameters");
    }
    params.validate();
  }

  public boolean isEqual(CertificateSecretParameters params, CertificateSecretParameters params2) {
    return EqualsBuilder.reflectionEquals(params, params2);
  }
}
