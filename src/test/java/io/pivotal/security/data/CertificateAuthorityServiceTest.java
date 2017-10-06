package io.pivotal.security.data;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.PermissionOperation;
import io.pivotal.security.util.CertificateReader;
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

  private static final String CREDENTIAL_NAME = "/expectedCredential";
  private static final String USER_NAME = "expectedUser";
  private CertificateAuthorityService certificateAuthorityService;
  private CredentialVersionDataService credentialVersionDataService;
  private CertificateCredentialValue certificate;
  private CertificateCredential certificateCredential;
  private PermissionsDataService permissionService;
  private UserContext userContext;

  @Before
  public void beforeEach() {
    certificate = new CertificateCredentialValue(null, SELF_SIGNED_CA_CERT, "my-key", null);
    certificateCredential = mock(CertificateCredential.class);

    permissionService = mock(PermissionsDataService.class);
    userContext = mock(UserContext.class);
    when(userContext.getAclUser()).thenReturn(USER_NAME);
    when(certificateCredential.getName()).thenReturn(CREDENTIAL_NAME);
    when(permissionService.hasPermission(USER_NAME, CREDENTIAL_NAME, PermissionOperation.READ))
        .thenReturn(true);

    credentialVersionDataService = mock(CredentialVersionDataService.class);
    certificateAuthorityService = new CertificateAuthorityService(credentialVersionDataService, permissionService);
  }

  @Test
  public void findMostRecent_whenACaDoesNotExist_throwsException() {
    when(credentialVersionDataService.findMostRecent(any(String.class))).thenReturn(null);

    try {
      certificateAuthorityService.findMostRecent(userContext, "any ca name");
    } catch (EntryNotFoundException pe) {
      assertThat(pe.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void findMostRecent_whenCaNameRefersToNonCa_throwsException() {
    when(credentialVersionDataService.findMostRecent(any(String.class))).thenReturn(mock(PasswordCredential.class));
    when(permissionService.hasPermission(USER_NAME, "any non-ca name", PermissionOperation.READ))
        .thenReturn(true);

    try {
      certificateAuthorityService.findMostRecent(userContext, "any non-ca name");
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.not_a_ca_name"));
    }
  }

  @Test
  public void findMostRecent_givenExistingCa_returnsTheCa() {
    CertificateReader certificateReader = mock(CertificateReader.class);
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME)).thenReturn(certificateCredential);
    when(certificateCredential.getPrivateKey()).thenReturn("my-key");
    when(certificateCredential.getParsedCertificate()).thenReturn(certificateReader);
    when(certificateReader.isCa()).thenReturn(true);
    when(certificateCredential.getCertificate()).thenReturn(SELF_SIGNED_CA_CERT);

    assertThat(certificateAuthorityService.findMostRecent(userContext, CREDENTIAL_NAME),
        samePropertyValuesAs(certificate));
  }

  @Test
  public void findMostRecent_whenCredentialIsNotACa_throwsException() {
    when(credentialVersionDataService.findMostRecent("actually-a-password"))
        .thenReturn(new PasswordCredential());

    try {
      certificateAuthorityService.findMostRecent(userContext, "actually-a-password");
    } catch (EntryNotFoundException pe) {
      assertThat(pe.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void findMostRecent_whenCertificateIsNotACa_throwsException() {
    CertificateCredential notACertificateAuthority = mock(CertificateCredential.class);
    when(notACertificateAuthority.getParsedCertificate()).thenReturn(mock(CertificateReader.class));
    when(notACertificateAuthority.getCertificate()).thenReturn(SIMPLE_SELF_SIGNED_TEST_CERT);
    when(credentialVersionDataService.findMostRecent(CREDENTIAL_NAME))
        .thenReturn(notACertificateAuthority);


    try {
      certificateAuthorityService.findMostRecent(userContext, CREDENTIAL_NAME);
    } catch (ParameterizedValidationException pe) {
      assertThat(pe.getMessage(), equalTo("error.cert_not_ca"));
    }
  }
}
