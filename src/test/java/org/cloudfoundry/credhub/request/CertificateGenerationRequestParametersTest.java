package org.cloudfoundry.credhub.request;

import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static junit.framework.TestCase.fail;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

@RunWith(JUnit4.class)
public class CertificateGenerationRequestParametersTest {

  private CertificateGenerationRequestParameters subject;

  @Before
  public void beforeEach() {
    subject = new CertificateGenerationRequestParameters();
    subject.setCommonName("test");
    subject.setSelfSigned(true);
  }

  @Test
  public void validate_allowsAllValidExtendedKeyUsages() {
    String[] validExtendedKeyUsages = new String[]{"server_auth", "client_auth", "code_signing", "email_protection", "timestamping"};
    subject.setExtendedKeyUsage(validExtendedKeyUsages);

    subject.validate();
    //pass
  }

  @Test
  public void validate_rejectsInvalidExtendedKeyUsages() {
    subject.setExtendedKeyUsage(new String[]{"server_auth", "this_is_invalid"});

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_extended_key_usage"));
      assertThat(e.getParameters(), equalTo(new Object[]{"this_is_invalid"}));
    }
  }

  @Test
  public void validate_withoutSelfSigned_orIsCa_requiresCaName() {
    subject.setIsCa(false);
    subject.setSelfSigned(false);
    subject.setCommonName("foo");

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_signing_ca"));
    }
  }

  @Test
  public void validate_withSelfSigned_andIsCa_shouldNotThrow() {
    subject.setIsCa(true);
    subject.setSelfSigned(false);
    subject.setCommonName("foo");

    subject.validate();
    // pass
  }

  @Test
  public void validate_requiresDurationToBeLessThan3650Days() {
    subject.setDuration(3651);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_duration"));
    }
  }

  @Test
  public void validate_requiresADNParameter() {
    subject.setOrganization("");
    subject.setState("");
    subject.setCountry("");
    subject.setCommonName("");
    subject.setOrganizationUnit("");
    subject.setLocality("");

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.missing_certificate_parameters"));
    }
  }

  @Test
  public void validate_allowsAllValidKeyLengths() {
    subject.setKeyLength(2048);
    subject.validate();

    subject.setKeyLength(3072);
    subject.validate();

    subject.setKeyLength(4096);
    subject.validate();

    // pass
  }

  @Test
  public void validate_rejectsKeyLengthLessThan2048() {
    subject.setKeyLength(2047);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_key_length"));
    }
  }

  @Test
  public void validate_rejectsKeyLengthBetween2048And3072() {
    subject.setKeyLength(2222);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_key_length"));
    }
  }

  @Test
  public void validate_rejectsKeyLengthBetween3072And4096() {
    subject.setKeyLength(4000);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_key_length"));
    }
  }


  @Test
  public void validate_rejectsKeyLengthGreaterThan4096() {
    subject.setKeyLength(4097);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_key_length"));
    }
  }

  @Test
  public void validate_allowsValidAlternativeNames() {
    subject.setAlternativeNames(new String[]{"1.1.1.1", "example.com", "foo.pivotal.io", "*.pivotal.io"});

    subject.validate();

    // pass
  }

  @Test
  public void validate_rejectsInvalidDNSCharactersInAlternativeNames() {
    try {
      subject.setAlternativeNames(new String[]{"foo!@#$%^&*()_-+=.com"});
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_alternate_name"));
    }
  }

  @Test
  public void validate_rejectsSpaceCharacterInAlternativeNames() {
    try {
      subject.setAlternativeNames(new String[]{"foo pivotal.io"});
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_alternate_name"));
    }
  }

  @Test
  public void validate_rejectsInvalidIpAddressInAlternativeNames() {
    try {
      subject.setAlternativeNames(new String[]{"1.2.3.999"});
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_alternate_name"));
    }
  }

  @Test
  public void validate_rejectsEmailAddressesInAlternativeNames() {
    // email addresses are allowed in certificate spec,
    // but we do not allow them per PM requirements
    try {
      subject.setAlternativeNames(new String[]{"x@y.com"});
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_alternate_name"));
    }
  }

  @Test
  public void validate_rejectsUrlsInAlternativeNames() {
    try {
      subject.setAlternativeNames(new String[]{"https://foo.com"});
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.invalid_alternate_name"));
    }
  }

  @Test
  public void validate_rejectsCommonNamesThatAreTooLong() {
    String maxLengthCommonName = "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setCommonName(maxLengthCommonName);
    subject.validate();

    String overlyLongCommonName = "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setCommonName(overlyLongCommonName);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"common name", 64}));
    }
  }

  @Test
  public void validate_rejectsOrganizationsThatAreTooLong() {
    String maxLengthOrganization= "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganization(maxLengthOrganization);
    subject.validate();

    String overlyLongOrganization= "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganization(overlyLongOrganization);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"organization", 64}));
    }
  }

  @Test
  public void validate_rejectsOrganizationUnitsThatAreTooLong() {
    String maxLengthOrganizationUnit = "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganizationUnit(maxLengthOrganizationUnit);
    subject.validate();

    String overlyLongOrganizationUnit = "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganizationUnit(overlyLongOrganizationUnit);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"organization unit", 64}));
    }
  }

  @Test
  public void validate_rejectsLocalitiesThatAreTooLong() {
    String maxLengthLocality = "128_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setLocality(maxLengthLocality);
    subject.validate();

    String overlyLongLocality = "129__abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setLocality(overlyLongLocality);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"locality", 128}));
    }
  }

  @Test
  public void validate_rejectsStatesThatAreTooLong() {
    String maxLengthState = "128_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setState(maxLengthState);
    subject.validate();

    String overlyLongState = "129__abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setState(overlyLongState);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"state", 128}));
    }
  }

  @Test
  public void validate_rejectsCountriesThatAreTooLong() {
    String maxLengthCountry = "ca";
    subject.setCountry(maxLengthCountry);
    subject.validate();

    String overlyLongCountry = "usa";
    subject.setCountry(overlyLongCountry);

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"country", 2}));
    }
  }

  @Test
  public void validate_rejectsAlternativeNamesThatAreTooLong() {
    String maxLengthAlternativeName = "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz012345.com";
    subject.setAlternativeNames(new String[]{"abc.com", maxLengthAlternativeName});
    subject.validate();

    String overlyLongAlternativeName = "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz012345.com";
    subject.setAlternativeNames(new String[]{"abc.com", overlyLongAlternativeName});

    try {
      subject.validate();
      fail("should throw");
    } catch (ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_certificate_parameter"));
      assertThat(e.getParameters(), equalTo(new Object[]{"alternative name", 64}));
    }
  }
}
