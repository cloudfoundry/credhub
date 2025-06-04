package org.cloudfoundry.credhub.requests;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.exceptions.InvalidAlternateNameCertificateException;
import org.cloudfoundry.credhub.exceptions.InvalidKeyLengthCertificateException;
import org.cloudfoundry.credhub.exceptions.MissingSigningCACertificateException;
import org.cloudfoundry.credhub.exceptions.NoSubjectCertificateException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.exceptions.SelfSignedCACertificateException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

public class CertificateGenerationRequestParametersTest {

  private CertificateGenerationRequestParameters subject;

  @BeforeEach
  public void beforeEach() {
    subject = new CertificateGenerationRequestParameters();
    subject.setCommonName("test");
    subject.setSelfSigned(true);
  }

  @Test
  public void validate_allowsAllValidExtendedKeyUsages() {
    final String[] validExtendedKeyUsages = new String[]{"server_auth", "client_auth", "code_signing", "email_protection", "timestamping"};
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
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.INVALID_EXTENDED_KEY_USAGE));
      assertThat(e.getParameters(), equalTo(new Object[]{"this_is_invalid"}));
    }
  }

  @Test
  public void validate_notSelfSigned_andNotCa_requiresCaName() {
    subject.setCommonName("foo");

    subject.setCa(false);
    subject.setSelfSigned(false);
    subject.setCaName(null);

    assertThrows(MissingSigningCACertificateException.class, () -> subject.validate());
  }

  @Test
  public void validate_withCaName_requiresSelfSignedFalse() {
    subject.setCaName("test");
    subject.setSelfSigned(true);
    subject.setCommonName("foo");

    assertThrows(SelfSignedCACertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_withSelfSigned_andIsCa_shouldNotThrow() {
    subject.setCa(true);
    subject.setSelfSigned(false);
    subject.setCommonName("foo");

    subject.validate();
    // pass
  }

  @Test
  public void validate_requiresDurationToBeLessThan3650Days() {
    subject.setDuration(3651);

    assertThrows(ParameterizedValidationException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_requiresSubject() {
    subject.setOrganization("");
    subject.setState("");
    subject.setCountry("");
    subject.setCommonName("");
    subject.setOrganizationUnit("");
    subject.setLocality("");

    assertThrows(NoSubjectCertificateException.class, () ->
      subject.validate()
    );
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

    assertThrows(InvalidKeyLengthCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsKeyLengthBetween2048And3072() {
    subject.setKeyLength(2222);

    assertThrows(InvalidKeyLengthCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsKeyLengthBetween3072And4096() {
    subject.setKeyLength(4000);

    assertThrows(InvalidKeyLengthCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsKeyLengthGreaterThan4096() {
    subject.setKeyLength(4097);

    assertThrows(InvalidKeyLengthCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_allowsValidAlternativeNames() {
    subject.setAlternativeNames(new String[]{"1.1.1.1", "example.com", "foo.pivotal.io", "*.pivotal.io"});

    subject.validate();

    // pass
  }

  @Test
  public void validate_rejectsInvalidDNSCharactersInAlternativeNames() {
    subject.setAlternativeNames(new String[]{"foo!@#$%^&*()_-+=.com"});

    assertThrows(InvalidAlternateNameCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsSpaceCharacterInAlternativeNames() {
    subject.setAlternativeNames(new String[]{"foo pivotal.io"});

    assertThrows(InvalidAlternateNameCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsInvalidIpAddressInAlternativeNames() {
    subject.setAlternativeNames(new String[]{"1.2.3.999"});

    assertThrows(InvalidAlternateNameCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsEmailAddressesInAlternativeNames() {
    // email addresses are allowed in certificate spec,
    // but we do not allow them per PM requirements
    subject.setAlternativeNames(new String[]{"x@y.com"});

    assertThrows(InvalidAlternateNameCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsUrlsInAlternativeNames() {
    subject.setAlternativeNames(new String[]{"https://foo.com"});

    assertThrows(InvalidAlternateNameCertificateException.class, () ->
      subject.validate()
    );
  }

  @Test
  public void validate_rejectsCommonNamesThatAreTooLong() {
    final String maxLengthCommonName = "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setCommonName(maxLengthCommonName);
    subject.validate();

    final String overlyLongCommonName = "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setCommonName(overlyLongCommonName);

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"common name", 64}));
    }
  }

  @Test
  public void validate_rejectsOrganizationsThatAreTooLong() {
    final String maxLengthOrganization = "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganization(maxLengthOrganization);
    subject.validate();

    final String overlyLongOrganization = "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganization(overlyLongOrganization);

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"organization", 64}));
    }
  }

  @Test
  public void validate_rejectsOrganizationUnitsThatAreTooLong() {
    final String maxLengthOrganizationUnit = "64abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganizationUnit(maxLengthOrganizationUnit);
    subject.validate();

    final String overlyLongOrganizationUnit = "65_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setOrganizationUnit(overlyLongOrganizationUnit);

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"organization unit", 64}));
    }
  }

  @Test
  public void validate_rejectsLocalitiesThatAreTooLong() {
    final String maxLengthLocality = "128_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setLocality(maxLengthLocality);
    subject.validate();

    final String overlyLongLocality = "129__abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setLocality(overlyLongLocality);

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"locality", 128}));
    }
  }

  @Test
  public void validate_rejectsStatesThatAreTooLong() {
    final String maxLengthState = "128_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setState(maxLengthState);
    subject.validate();

    final String overlyLongState = "129__abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
    subject.setState(overlyLongState);

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"state", 128}));
    }
  }

  @Test
  public void validate_rejectsCountriesThatAreTooLong() {
    final String maxLengthCountry = "ca";
    subject.setCountry(maxLengthCountry);
    subject.validate();

    final String overlyLongCountry = "usa";
    subject.setCountry(overlyLongCountry);

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"country", 2}));
    }
  }

  @Test
  public void validate_rejectsAlternativeNamesThatAreTooLong() {
    final String maxLengthAlternativeName =
            RandomStringUtils.insecure().nextAlphabetic(57)
                    + "." + RandomStringUtils.insecure().nextNumeric(63) + "."
                    + RandomStringUtils.insecure().nextAlphabetic(63) + "."
                    + RandomStringUtils.insecure().nextAlphabetic(63) + ".com";
    subject.setAlternativeNames(new String[]{"abc.com", maxLengthAlternativeName});
    subject.validate();


    final String overlyLongAlternativeName = "."
            + RandomStringUtils.insecure().nextAlphabetic(58)
            + "." + RandomStringUtils.insecure().nextNumeric(63) + "."
            + RandomStringUtils.insecure().nextAlphabetic(63) +
            "." + RandomStringUtils.insecure().nextAlphabetic(63) + ".co";
    subject.setAlternativeNames(new String[]{"abc.com", overlyLongAlternativeName});

    try {
      subject.validate();
      fail("should throw");
    } catch (final ParameterizedValidationException e) {
      assertThat(e.getMessage(), equalTo(ErrorMessages.Credential.INVALID_CERTIFICATE_PARAMETER));
      assertThat(e.getParameters(), equalTo(new Object[]{"alternative name", 253}));
    }
  }
}
