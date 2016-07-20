package io.pivotal.security.controller.v1;

import io.pivotal.security.CredentialManagerApp;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.validation.ValidationException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
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
  public void constructsDNStringWhenOnlyRequiredParamsArePresent() throws Exception {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");

    assertThat(params.getDN().toString(), equalTo("O=My Organization,ST=My State,C=My Country"));
  }

  @Test
  public void canAddAlternativeNames() {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addAlternativeName("Alternative Name 1");
    params.addAlternativeName("Alternative Name 2");

    assertThat(params.getAlternativeNames(), contains("Alternative Name 1", "Alternative Name 2"));
  }

  @Test
  public void alternativeNamesConsideredForInequality() {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addAlternativeName("Alternative Name 1");
    params.addAlternativeName("Alternative Name 2");

    CertificateSecretParameters params2 = new CertificateSecretParameters();
    params2.setCountry("My Country");
    params2.setState("My State");
    params2.setOrganization("My Organization");
    params2.addAlternativeName("Alternative Name 1dif");
    params2.addAlternativeName("Alternative Name 2");

    assertThat(isEqual(params, params2), is(false));
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
  public void needAtLeastStateAndOrganizationAndCountry() {
    doValidateTest(false, "", "", "", "", "", "");
    doValidateTest(false, "", "", "", "", "", "a");
    doValidateTest(false, "", "", "", "", "b", "");
    doValidateTest(false, "", "", "", "", "b", "a");
    doValidateTest(false, "", "", "", "c", "", "");
    doValidateTest(false, "", "", "", "c", "", "a");
    doValidateTest(false, "", "", "", "c", "b", "");
    doValidateTest(false, "", "", "", "c", "b", "a");
    doValidateTest(false, "", "", "d", "", "", "");
    doValidateTest(false, "", "", "d", "", "", "a");
    doValidateTest(false, "", "", "d", "", "b", "");
    doValidateTest(false, "", "", "d", "", "b", "a");
    doValidateTest(false, "", "", "d", "c", "", "");
    doValidateTest(false, "", "", "d", "c", "", "a");
    doValidateTest(false, "", "", "d", "c", "b", "");
    doValidateTest(false, "", "", "d", "c", "b", "a");
    doValidateTest(false, "", "e", "", "", "", "");
    doValidateTest(false, "", "e", "", "", "", "a");
    doValidateTest(false, "", "e", "", "", "b", "");
    doValidateTest(false, "", "e", "", "", "b", "a");
    doValidateTest(false, "", "e", "", "c", "", "");
    doValidateTest(false, "", "e", "", "c", "", "a");
    doValidateTest(false, "", "e", "", "c", "b", "");
    doValidateTest(false, "", "e", "", "c", "b", "a");
    doValidateTest(false, "", "e", "d", "", "", "");
    doValidateTest(false, "", "e", "d", "", "", "a");
    doValidateTest(false, "", "e", "d", "", "b", "");
    doValidateTest(false, "", "e", "d", "", "b", "a");
    doValidateTest(false, "", "e", "d", "c", "", "");
    doValidateTest(false, "", "e", "d", "c", "", "a");
    doValidateTest(false, "", "e", "d", "c", "b", "");
    doValidateTest(false, "", "e", "d", "c", "b", "a");
    doValidateTest(false, "f", "", "", "", "", "");
    doValidateTest(false, "f", "", "", "", "", "a");
    doValidateTest(false, "f", "", "", "", "b", "");
    doValidateTest(false, "f", "", "", "", "b", "a");
    doValidateTest(false, "f", "", "", "c", "", "");
    doValidateTest(false, "f", "", "", "c", "", "a");
    doValidateTest(false, "f", "", "", "c", "b", "");
    doValidateTest(false, "f", "", "", "c", "b", "a");
    doValidateTest(false, "f", "", "d", "", "", "");
    doValidateTest(false, "f", "", "d", "", "", "a");
    doValidateTest(false, "f", "", "d", "", "b", "");
    doValidateTest(false, "f", "", "d", "", "b", "a");
    doValidateTest(false, "f", "", "d", "c", "", "");
    doValidateTest(false, "f", "", "d", "c", "", "a");
    doValidateTest(false, "f", "", "d", "c", "b", "");
    doValidateTest(false, "f", "", "d", "c", "b", "a");
    doValidateTest(false, "f", "e", "", "", "", "");
    doValidateTest(false, "f", "e", "", "", "", "a");
    doValidateTest(false, "f", "e", "", "", "b", "");
    doValidateTest(false, "f", "e", "", "", "b", "a");
    doValidateTest(false, "f", "e", "", "c", "", "");
    doValidateTest(false, "f", "e", "", "c", "", "a");
    doValidateTest(false, "f", "e", "", "c", "b", "");
    doValidateTest(false, "f", "e", "", "c", "b", "a");
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
      thrown.expect(ValidationException.class);
      thrown.expectMessage("error.missing_certificate_parameters");
    }
    params.validate();
  }

  public boolean isEqual(CertificateSecretParameters params, CertificateSecretParameters params2) {
    return EqualsBuilder.reflectionEquals(params, params2);
  }
}
