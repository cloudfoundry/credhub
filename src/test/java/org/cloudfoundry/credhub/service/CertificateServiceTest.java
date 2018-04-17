package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(JUnit4.class)
public class CertificateServiceTest {

  CertificateService subject;

  @Mock
  CertificateVersionDataService certificateVersionDataService;

  @Mock
  PermissionCheckingService permissionCheckingService;

  UserContextHolder userContextHolder;
  UserContext userContext;
  private String credentialUuid = "knownCredentialUuid";
  private CredentialVersion credentialVersion = new CertificateCredentialVersion();
  private String credentialName = "certificateCredential";
  private String actor = "Actor";


  @Before
  public void setup() {
    initMocks(this);
    userContext = mock(UserContext.class);
    userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);
    subject = new CertificateService(certificateVersionDataService,
        permissionCheckingService,
        userContextHolder);
    credentialVersion.createName(credentialName);
    when(userContext.getActor()).thenReturn(actor);
    when(certificateVersionDataService.findByCredentialUUID(credentialUuid)).thenReturn(credentialVersion);
  }

  @Test
  public void findByUuid_ReturnsCertificateWithMatchingUuid() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
        .thenReturn(true);

    CertificateCredentialVersion certificate = subject.findByCredentialUuid(credentialUuid);

    assertThat(certificate, not(nullValue()));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsIfUserDoesNotHaveReadAccess() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
        .thenReturn(false);

    subject.findByCredentialUuid(credentialUuid);
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidNotFound() {
    when(certificateVersionDataService.findByCredentialUUID("UnknownUuid")).thenReturn(null);

    subject.findByCredentialUuid("UnknownUuid");
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidMatchesNonCertificateCredential() {
    when(certificateVersionDataService.findByCredentialUUID("rsaUuid")).thenReturn(null);

    subject.findByCredentialUuid("rsaUuid");
  }
}
