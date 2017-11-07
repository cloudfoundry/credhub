package io.pivotal.security.service;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.RsaCredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.List;

import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(JUnit4.class)
public class CertificateServiceTest {

  CertificateService subject;

  private List<EventAuditRecordParameters> auditRecordParameters;

  @Mock
  CredentialVersionDataService credentialVersionDataService;

  @Mock
  PermissionCheckingService permissionCheckingService;

  UserContextHolder userContextHolder;
  UserContext userContext;
  private String certificateUuid = "knownUuid";
  private CredentialVersion credentialVersion = new CertificateCredentialVersion();
  private String credentialName = "certificateCredential";
  private String actor = "Actor";


  @Before
  public void setup() {
    initMocks(this);
    auditRecordParameters = new ArrayList<>();
    userContext = mock(UserContext.class);
    userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);
    subject = new CertificateService(credentialVersionDataService,
        permissionCheckingService,
        userContextHolder);
    credentialVersion.createName(credentialName);
    when(userContext.getActor()).thenReturn(actor);
    when(credentialVersionDataService.findByUuid(certificateUuid)).thenReturn(credentialVersion);
  }

  @Test
  public void findByUuid_ReturnsCertificateWithMatchingUuidAndPersistsAuditEntry() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
        .thenReturn(true);

    CertificateCredentialVersion certificate = subject.findByUuid(certificateUuid, auditRecordParameters);

    assertThat(certificate, not(nullValue()));
    assertThat(auditRecordParameters.size(), equalTo(1));
    EventAuditRecordParameters auditRecord = this.auditRecordParameters.get(0);
    assertThat(auditRecord.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    assertThat(auditRecord.getCredentialName(), equalTo(credentialName));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsIfUserDoesNotHaveReadAccessAndPersistsAuditEntry() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
        .thenReturn(false);

    subject.findByUuid(certificateUuid, auditRecordParameters);
    assertThat(auditRecordParameters.size(), equalTo(1));
    EventAuditRecordParameters auditRecord = this.auditRecordParameters.get(0);
    assertThat(auditRecord.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidNotFoundAndPersistsAuditEntry() {
    when(credentialVersionDataService.findByUuid("UnknownUuid")).thenReturn(null);

    subject.findByUuid("UnknownUuid", auditRecordParameters);
    assertThat(auditRecordParameters.size(), equalTo(1));
    EventAuditRecordParameters auditRecord = this.auditRecordParameters.get(0);
    assertThat(auditRecord.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidMatchesNonCertificateCredential() {
    CredentialVersion credentialVersion = new RsaCredentialVersion();
    when(credentialVersionDataService.findByUuid("rsaUuid")).thenReturn(credentialVersion);

    subject.findByUuid("rsaUuid", auditRecordParameters);
  }
}
