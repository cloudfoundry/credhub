package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.CertificateVersionDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.RsaCredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.List;

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
    auditRecordParameters = new ArrayList<>();
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
  public void findByUuid_ReturnsCertificateWithMatchingUuidAndPersistsAuditEntry() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
        .thenReturn(true);

    CertificateCredentialVersion certificate = subject.findByCredentialUuid(credentialUuid, auditRecordParameters);

    assertThat(certificate, not(nullValue()));
    assertThat(auditRecordParameters.size(), equalTo(1));
    EventAuditRecordParameters auditRecord = this.auditRecordParameters.get(0);
    assertThat(auditRecord.getAuditingOperationCode(), equalTo(AuditingOperationCode.CREDENTIAL_ACCESS));
    assertThat(auditRecord.getCredentialName(), equalTo(credentialName));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsIfUserDoesNotHaveReadAccessAndPersistsAuditEntry() {
    when(permissionCheckingService.hasPermission(actor, credentialName, PermissionOperation.READ))
        .thenReturn(false);

    subject.findByCredentialUuid(credentialUuid, auditRecordParameters);
    assertThat(auditRecordParameters.size(), equalTo(1));
    EventAuditRecordParameters auditRecord = this.auditRecordParameters.get(0);
    assertThat(auditRecord.getAuditingOperationCode(), equalTo(AuditingOperationCode.CREDENTIAL_ACCESS));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidNotFoundAndPersistsAuditEntry() {
    when(certificateVersionDataService.findByCredentialUUID("UnknownUuid")).thenReturn(null);

    subject.findByCredentialUuid("UnknownUuid", auditRecordParameters);
    assertThat(auditRecordParameters.size(), equalTo(1));
    EventAuditRecordParameters auditRecord = this.auditRecordParameters.get(0);
    assertThat(auditRecord.getAuditingOperationCode(), equalTo(AuditingOperationCode.CREDENTIAL_ACCESS));
  }

  @Test(expected = EntryNotFoundException.class)
  public void findByUuid_ThrowsEntryNotFoundIfUuidMatchesNonCertificateCredential() {
    CredentialVersion credentialVersion = new RsaCredentialVersion();
    when(certificateVersionDataService.findByCredentialUUID("rsaUuid")).thenReturn(null);

    subject.findByCredentialUuid("rsaUuid", auditRecordParameters);
  }
}
