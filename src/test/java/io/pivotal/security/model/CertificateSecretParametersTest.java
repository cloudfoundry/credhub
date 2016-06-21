package io.pivotal.security.model;

import io.pivotal.security.CredentialManagerApp;
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

    assertThat(params.getDNString(), equalTo("O=My Organization,ST=My State,C=My Country,CN=My Common Name,OU=My Organization Unit,L=My Locality"));
  }

  @Test
  public void constructsDNStringWhenOnlyRequiredParamsArePresent() throws Exception {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");

    assertThat(params.getDNString(), equalTo("O=My Organization,ST=My State,C=My Country"));
  }

  @Test
  public void canAddAlternativeNames() {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addAlternateName("Alternate Name 1");
    params.addAlternateName("Alternate Name 2");

    assertThat(params.getAlternateNames(), contains("Alternate Name 1", "Alternate Name 2"));
  }

  @Test
  public void alternativeNamesConsideredForInequality() {
    CertificateSecretParameters params = new CertificateSecretParameters();
    params.setCountry("My Country");
    params.setState("My State");
    params.setOrganization("My Organization");
    params.addAlternateName("Alternate Name 1");
    params.addAlternateName("Alternate Name 2");

    CertificateSecretParameters params2 = new CertificateSecretParameters();
    params2.setCountry("My Country");
    params2.setState("My State");
    params2.setOrganization("My Organization");
    params2.addAlternateName("Alternate Name 1dif");
    params2.addAlternateName("Alternate Name 2");

    assertThat(params.equals(params2), is(false));
  }

  @Test
  public void needAtLeastStateAndOrganizationAndCountry() {
    doTest(false, "", "", "", "", "", "");
    doTest(false, "", "", "", "", "", "a");
    doTest(false, "", "", "", "", "b", "");
    doTest(false, "", "", "", "", "b", "a");
    doTest(false, "", "", "", "c", "", "");
    doTest(false, "", "", "", "c", "", "a");
    doTest(false, "", "", "", "c", "b", "");
    doTest(false, "", "", "", "c", "b", "a");
    doTest(false, "", "", "d", "", "", "");
    doTest(false, "", "", "d", "", "", "a");
    doTest(false, "", "", "d", "", "b", "");
    doTest(false, "", "", "d", "", "b", "a");
    doTest(false, "", "", "d", "c", "", "");
    doTest(false, "", "", "d", "c", "", "a");
    doTest(false, "", "", "d", "c", "b", "");
    doTest(false, "", "", "d", "c", "b", "a");
    doTest(false, "", "e", "", "", "", "");
    doTest(false, "", "e", "", "", "", "a");
    doTest(false, "", "e", "", "", "b", "");
    doTest(false, "", "e", "", "", "b", "a");
    doTest(false, "", "e", "", "c", "", "");
    doTest(false, "", "e", "", "c", "", "a");
    doTest(false, "", "e", "", "c", "b", "");
    doTest(false, "", "e", "", "c", "b", "a");
    doTest(false, "", "e", "d", "", "", "");
    doTest(false, "", "e", "d", "", "", "a");
    doTest(false, "", "e", "d", "", "b", "");
    doTest(false, "", "e", "d", "", "b", "a");
    doTest(false, "", "e", "d", "c", "", "");
    doTest(false, "", "e", "d", "c", "", "a");
    doTest(false, "", "e", "d", "c", "b", "");
    doTest(false, "", "e", "d", "c", "b", "a");
    doTest(false, "f", "", "", "", "", "");
    doTest(false, "f", "", "", "", "", "a");
    doTest(false, "f", "", "", "", "b", "");
    doTest(false, "f", "", "", "", "b", "a");
    doTest(false, "f", "", "", "c", "", "");
    doTest(false, "f", "", "", "c", "", "a");
    doTest(false, "f", "", "", "c", "b", "");
    doTest(false, "f", "", "", "c", "b", "a");
    doTest(false, "f", "", "d", "", "", "");
    doTest(false, "f", "", "d", "", "", "a");
    doTest(false, "f", "", "d", "", "b", "");
    doTest(false, "f", "", "d", "", "b", "a");
    doTest(false, "f", "", "d", "c", "", "");
    doTest(false, "f", "", "d", "c", "", "a");
    doTest(false, "f", "", "d", "c", "b", "");
    doTest(false, "f", "", "d", "c", "b", "a");
    doTest(false, "f", "e", "", "", "", "");
    doTest(false, "f", "e", "", "", "", "a");
    doTest(false, "f", "e", "", "", "b", "");
    doTest(false, "f", "e", "", "", "b", "a");
    doTest(false, "f", "e", "", "c", "", "");
    doTest(false, "f", "e", "", "c", "", "a");
    doTest(false, "f", "e", "", "c", "b", "");
    doTest(false, "f", "e", "", "c", "b", "a");
    doTest(true, "f", "e", "d", "", "", "");
    doTest(true, "f", "e", "d", "", "", "a");
    doTest(true, "f", "e", "d", "", "b", "");
    doTest(true, "f", "e", "d", "", "b", "a");
    doTest(true, "f", "e", "d", "c", "", "");
    doTest(true, "f", "e", "d", "c", "", "a");
    doTest(true, "f", "e", "d", "c", "b", "");
    doTest(true, "f", "e", "d", "c", "b", "a");
  }

  private void doTest(boolean isValid, String organization, String state, String country, String commonName, String organizationUnit, String locality) {
    CertificateSecretParameters params = new CertificateSecretParameters()
        .setOrganization(organization)
        .setState(state)
        .setCountry(country)
        .setCommonName(commonName)
        .setOrganizationUnit(organizationUnit)
        .setLocality(locality);

    if (!isValid) {
      thrown.expect(ValidationException.class);
    }
    params.validate();
  }
}
