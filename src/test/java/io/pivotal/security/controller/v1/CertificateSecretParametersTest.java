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
  public void constructsDNStringWhenOnlyOneParamIsPresent() throws Exception {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");

    assertThat(params.getDN().toString(), equalTo("C=My Country"));
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
      thrown.expect(ValidationException.class);
      thrown.expectMessage("error.missing_certificate_parameters");
    }
    params.validate();
  }

  public boolean isEqual(CertificateSecretParameters params, CertificateSecretParameters params2) {
    return EqualsBuilder.reflectionEquals(params, params2);
  }
}
