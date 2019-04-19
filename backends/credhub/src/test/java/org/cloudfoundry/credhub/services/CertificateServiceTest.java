package org.cloudfoundry.credhub.services;

import org.cloudfoundry.credhub.PermissionOperation;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.certificates.CertificateService;
import org.cloudfoundry.credhub.data.DefaultCertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
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

  private CertificateService subject;

  @Mock
  private DefaultCertificateVersionDataService certificateVersionDataService;

  @Mock
  private PermissionCheckingService permissionCheckingService;

  private UserContextHolder userContextHolder;
  private UserContext userContext;
  private final static String credentialUuid = "knownCredentialUuid";
  private final static String credentialName = "certificateCredential";
  private final static String actor = "Actor";

  private final CredentialVersion credentialVersion = new CertificateCredentialVersion();

  @Before
  public void setup() {
    initMocks(this);
    userContext = mock(UserContext.class);
    userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);
    subject = new CertificateService(
      certificateVersionDataService,
      permissionCheckingService,
      userContextHolder
    );
    credentialVersion.createName(credentialName);
    when(userContext.getActor()).thenReturn(actor);
    when(certificateVersionDataService.findByCredentialUUID(credentialUuid)).thenReturn(credentialVersion);
  }

  @Test
  public void findByUuid_ReturnsCertificateWithMatchingUuid() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
      .thenReturn(true);

    final CertificateCredentialVersion certificate = subject.findByCredentialUuid(credentialUuid);

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
