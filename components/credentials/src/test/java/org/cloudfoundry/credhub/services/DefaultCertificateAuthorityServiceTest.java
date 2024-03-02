package org.cloudfoundry.credhub.services;

import java.security.Security;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.utils.BouncyCastleFipsConfigurer;
import org.cloudfoundry.credhub.utils.CertificateReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static org.cloudfoundry.credhub.utils.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultCertificateAuthorityServiceTest {

  private static final String CREDENTIAL_NAME = "/expectedCredential";
  private static final String TRANSITIONAL_CREDENTIAL_NAME = "/transitionalCredential";
  private CertificateAuthorityService certificateAuthorityService;
  private DefaultCertificateVersionDataService certificateVersionDataService;
  private CertificateCredentialValue certificate;
  private CertificateCredentialVersion certificateCredential;
  private CertificateCredentialVersion transitionalCertificateCredential;

  @BeforeAll
  public static void setUpAll() {
    BouncyCastleFipsConfigurer.configure();
  }

  @BeforeEach
  public void beforeEach() {
    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

    certificate = new CertificateCredentialValue(null, SELF_SIGNED_CA_CERT, "my-key", null, true, true, false, false);
    certificateCredential = mock(CertificateCredentialVersion.class);
    transitionalCertificateCredential = mock(CertificateCredentialVersion.class);

    when(certificateCredential.getName()).thenReturn(CREDENTIAL_NAME);
    when(transitionalCertificateCredential.getName()).thenReturn(TRANSITIONAL_CREDENTIAL_NAME);
    when(transitionalCertificateCredential.isVersionTransitional()).thenReturn(true);

    certificateVersionDataService = mock(DefaultCertificateVersionDataService.class);
    certificateAuthorityService = new DefaultCertificateAuthorityService(certificateVersionDataService);
  }

  @Test
  public void findTransitionalVersion_whenATransitionalCaDoesNotExist_returnsNull() {
    when(certificateVersionDataService.findBothActiveCertAndTransitionalCert(CREDENTIAL_NAME)).thenReturn(
      Collections.singletonList(certificateCredential));

    CertificateCredentialValue transitionalVersion = certificateAuthorityService.findTransitionalVersion(CREDENTIAL_NAME);
    assertNull(transitionalVersion);
  }

  @Test
  public void findTransitionalVersion_givenExistingTransitionalCa_returnsTheTransitionalCa() {
    final CertificateReader certificateReader = mock(CertificateReader.class);
    when(transitionalCertificateCredential.getParsedCertificate()).thenReturn(certificateReader);
    when(certificateReader.isCa()).thenReturn(true);
    when(certificateVersionDataService.findBothActiveCertAndTransitionalCert(CREDENTIAL_NAME)).thenReturn(Arrays.asList(certificateCredential, transitionalCertificateCredential));
    when(transitionalCertificateCredential.getCertificate()).thenReturn(SELF_SIGNED_CA_CERT);

    assertThat(certificateAuthorityService.findTransitionalVersion(CREDENTIAL_NAME).getCertificate(),
      equalTo(transitionalCertificateCredential.getCertificate()));
  }

  @Test
  public void findActiveVersion_whenACaDoesNotExist_throwsException() {
    when(certificateVersionDataService.findActive(any(String.class))).thenReturn(null);

    try {
      certificateAuthorityService.findActiveVersion("any ca name");
    } catch (final EntryNotFoundException pe) {
      assertThat(pe.getMessage(), equalTo(ErrorMessages.Credential.CERTIFICATE_ACCESS));
    }
  }

  @Test
  public void findActiveVersion_whenCaNameRefersToNonCa_throwsException() {
    when(certificateVersionDataService.findActive(any(String.class))).thenReturn(mock(PasswordCredentialVersion.class));

    try {
      certificateAuthorityService.findActiveVersion("any non-ca name");
    } catch (final ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo(ErrorMessages.NOT_A_CA_NAME));
    }
  }

  @Test
  public void findActiveVersion_givenExistingCa_returnsTheCa() {
    final CertificateReader certificateReader = mock(CertificateReader.class);
    when(certificateVersionDataService.findActive(CREDENTIAL_NAME)).thenReturn(certificateCredential);
    when(certificateCredential.getPrivateKey()).thenReturn("my-key");
    when(certificateCredential.getParsedCertificate()).thenReturn(certificateReader);
    when(certificateReader.isCa()).thenReturn(true);
    when(certificateCredential.isCertificateAuthority()).thenReturn(true);
    when(certificateCredential.isSelfSigned()).thenReturn(true);
    when(certificateCredential.getCertificate()).thenReturn(SELF_SIGNED_CA_CERT);
    when(certificateCredential.getGenerated()).thenReturn(false);
    when(certificateCredential.isVersionTransitional()).thenReturn(false);

    assertThat(certificateAuthorityService.findActiveVersion(CREDENTIAL_NAME),
      samePropertyValuesAs(certificate));
  }

  @Test
  public void findActiveVersion_whenCredentialIsNotACa_throwsException() {
    when(certificateVersionDataService.findActive("actually-a-password"))
      .thenReturn(new PasswordCredentialVersion());

    try {
      certificateAuthorityService.findActiveVersion("actually-a-password");
    } catch (final ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo(ErrorMessages.NOT_A_CA_NAME));
    } catch (final Exception e) {
      fail("expected EntryNotFoundException, but got " + e.getClass());
    }
  }

  @Test
  public void findActiveVersion_whenCertificateIsNotACa_throwsException() {
    final CertificateCredentialVersion notACertificateAuthority = mock(CertificateCredentialVersion.class);
    when(notACertificateAuthority.getParsedCertificate()).thenReturn(mock(CertificateReader.class));
    when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
    when(certificateVersionDataService.findActive(CREDENTIAL_NAME))
      .thenReturn(notACertificateAuthority);

    try {
      certificateAuthorityService.findActiveVersion(CREDENTIAL_NAME);
    } catch (final ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo(ErrorMessages.CERT_NOT_CA));
    }
  }
}
