package io.pivotal.security.data;

import io.pivotal.security.config.BouncyCastleProviderConfiguration;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CA_CERT;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CertificateAuthorityServiceTest {

  CertificateAuthorityService certificateAuthorityService;
  CredentialDataService credentialDataService;
  CertificateCredentialValue certificate;
  CertificateCredential certificateCredential;

  @Before
  public void beforeEach() {
    certificate = new CertificateCredentialValue(null, SELF_SIGNED_CA_CERT, "my-key", null);
    certificateCredential = mock(CertificateCredential.class);

    credentialDataService = mock(CredentialDataService.class);
    certificateAuthorityService = new CertificateAuthorityService(credentialDataService);

    new BouncyCastleProviderConfiguration().bouncyCastleProvider();
  }

  @Test
  public void findMostRecent_whenACaDoesNotExist_throwsException() {
    when(credentialDataService.findMostRecent(any(String.class))).thenReturn(null);

    try {
      certificateAuthorityService.findMostRecent("any ca name");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.ca_not_found"));
    }
  }

  @Test
  public void findMostRecent_givenExistingCa_returnsTheCa() {
    when(credentialDataService.findMostRecent("my-ca-name")).thenReturn(certificateCredential);
    when(certificateCredential.getPrivateKey()).thenReturn("my-key");
    when(certificateCredential.getCertificate()).thenReturn(SELF_SIGNED_CA_CERT);

    assertThat(certificateAuthorityService.findMostRecent("my-ca-name"),
        samePropertyValuesAs(certificate));
  }

  @Test
  public void findMostRecent_whenCredentialIsNotACa_throwsException() {
    when(credentialDataService.findMostRecent("actually-a-password"))
        .thenReturn(new PasswordCredential());

    try {
      certificateAuthorityService.findMostRecent("actually-a-password");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.ca_not_found"));
    }
  }

  @Test
  public void findMostRecent_whenCertificateIsNotACa_throwsException() {
    CertificateCredential notACertificateAuthority = mock(CertificateCredential.class);
    when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
    when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
    when(credentialDataService.findMostRecent("just-a-certificate"))
        .thenReturn(notACertificateAuthority);



    try {
      certificateAuthorityService.findMostRecent("just-a-certificate");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.cert_not_ca"));
    }
  }
}
