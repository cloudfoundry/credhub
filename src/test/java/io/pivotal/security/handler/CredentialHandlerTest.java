package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.view.CredentialView;
import io.pivotal.security.view.DataResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.time.Instant;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialHandlerTest {
  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final Instant VERSION1_CREATED_AT = Instant.ofEpochMilli(555555555);
  private static final Instant VERSION2_CREATED_AT = Instant.ofEpochMilli(777777777);
  private static final String UUID_STRING = "fake-uuid";

  private CredentialHandler subject;
  private CredentialDataService credentialDataService;
  private PermissionService permissionService;

  private UserContext userContext;
  private SshCredential version1;
  private SshCredential version2;

  @Before
  public void beforeEach() {
    Encryptor encryptor = mock(Encryptor.class);

    credentialDataService = mock(CredentialDataService.class);
    permissionService = mock(PermissionService.class);
    subject = new CredentialHandler(credentialDataService, permissionService);

    userContext = mock(UserContext.class);

    version1 = new SshCredential(CREDENTIAL_NAME);
    version1.setVersionCreatedAt(VERSION1_CREATED_AT);
    version1.setEncryptor(encryptor);

    version2 = new SshCredential(CREDENTIAL_NAME);
    version2.setVersionCreatedAt(VERSION2_CREATED_AT);
    version2.setEncryptor(encryptor);
  }

  @Test
  public void deleteCredential_whenTheDeletionSucceeds_deletesTheCredential() {
    when(credentialDataService.delete(CREDENTIAL_NAME)).thenReturn(true);
    when(permissionService.hasCredentialDeletePermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    subject.deleteCredential(userContext, CREDENTIAL_NAME);

    verify(credentialDataService, times(1)).delete(CREDENTIAL_NAME);
  }

  @Test
  public void deleteCredential_whenTheUserLacksPermission_throwsAnException() {
    when(permissionService.hasCredentialDeletePermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.deleteCredential(userContext, CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.acl.lacks_credential_write"));
    }
  }

  @Test
  public void deleteCredential_whenTheCredentialIsNotDeleted_throwsAnException() {
    when(permissionService.hasCredentialDeletePermission(any(), any()))
        .thenReturn(true);
    when(credentialDataService.delete(CREDENTIAL_NAME)).thenReturn(false);

    try {
      subject.deleteCredential(userContext, CREDENTIAL_NAME);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.acl.lacks_credential_write"));
    }
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialExists_returnsADataResponse() {
    List<Credential> credentials = newArrayList(version1, version2);
    when(credentialDataService.findAllByName(CREDENTIAL_NAME))
        .thenReturn(credentials);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    DataResponse response = subject.getAllCredentialVersions(userContext,
        new EventAuditRecordParameters(), CREDENTIAL_NAME);

    List<CredentialView> responseCredentials = response.getData();
    assertThat(responseCredentials, hasSize(2));
    assertThat(responseCredentials.get(0).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(responseCredentials.get(0).getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    assertThat(responseCredentials.get(1).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(responseCredentials.get(1).getVersionCreatedAt(), equalTo(VERSION2_CREATED_AT));
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialExists_setsCorrectAuditingParameters() {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();
    List<Credential> credentials = newArrayList(version1);
    when(credentialDataService.findAllByName(CREDENTIAL_NAME))
        .thenReturn(credentials);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    subject.getAllCredentialVersions(userContext, auditRecordParameters, CREDENTIAL_NAME);
    assertThat(auditRecordParameters.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParameters.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getAllCredentialVersions_whenTheUserLacksPermission_throwsException() {
    List<Credential> credentials = newArrayList(version1, version2);
    when(credentialDataService.findAllByName(CREDENTIAL_NAME))
        .thenReturn(credentials);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.getAllCredentialVersions(userContext, new EventAuditRecordParameters(),
          CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential_not_found"));
    }
  }

  @Test
  public void getAllCredentialVersions_whenTheUserLacksPermission_setsCorrectAuditingParameters() {
    List<Credential> credentials = newArrayList(version1);
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();
    when(credentialDataService.findAllByName(CREDENTIAL_NAME))
        .thenReturn(credentials);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.getAllCredentialVersions(userContext, auditRecordParameters, CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(auditRecordParameters.getCredentialName(), equalTo(CREDENTIAL_NAME));
    }
  }

  @Test
  public void getCredentialVersions_whenTheCredentialDoesNotExist_throwsException() {
    when(credentialDataService.findAllByName(CREDENTIAL_NAME))
        .thenReturn(emptyList());
    when(permissionService.hasCredentialReadPermission(any(), any()))
        .thenReturn(true);

    try {
      subject.getAllCredentialVersions(userContext, new EventAuditRecordParameters(),
          CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential_not_found"));
    }
  }

  @Test
  public void getCredentialVersions_whenTheCredentialDoesNotExist_setsCorrectAuditingParameter() {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();

    when(credentialDataService.findAllByName(CREDENTIAL_NAME))
        .thenReturn(emptyList());

    try {
      subject.getAllCredentialVersions(userContext, auditRecordParameters, CREDENTIAL_NAME
      );
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(auditRecordParameters.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialExists_returnsDataResponse() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    DataResponse response = subject.getMostRecentCredentialVersion(
        userContext,
        new EventAuditRecordParameters(), CREDENTIAL_NAME
    );
    List<CredentialView> responseCredentials = response.getData();

    assertThat(responseCredentials, hasSize(1));
    assertThat(responseCredentials.get(0).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(responseCredentials.get(0).getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialExists_setsCorrectAuditingParameters() {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    subject.getMostRecentCredentialVersion(userContext, auditRecordParameters, CREDENTIAL_NAME);

    assertThat(auditRecordParameters.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParameters.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialDoesNotExist_throwsException() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME))
        .thenReturn(null);

    try {
      subject.getMostRecentCredentialVersion(userContext, new EventAuditRecordParameters(),
          CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential_not_found"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheUserLacksPermission_throwsException() {
    when(credentialDataService.findMostRecent(CREDENTIAL_NAME))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.getMostRecentCredentialVersion(userContext, new EventAuditRecordParameters(),
          CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential_not_found"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheUserLacksPermission_setsCorrectAuditingParameters() {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();

    when(credentialDataService.findMostRecent(CREDENTIAL_NAME))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.getMostRecentCredentialVersion(userContext, auditRecordParameters, CREDENTIAL_NAME);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(auditRecordParameters.getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParameters.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_returnsDataResponse() {
    when(credentialDataService.findByUuid(UUID_STRING))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    CredentialView response = subject.getCredentialVersion(
        userContext,
        new EventAuditRecordParameters(), UUID_STRING
    );
    assertThat(response.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(response.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_setsCorrectAuditingParameters() {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();
    when(credentialDataService.findByUuid(UUID_STRING))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(true);

    subject.getCredentialVersion(userContext, auditRecordParameters, UUID_STRING);

    assertThat(auditRecordParameters.getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParameters.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getCredentialVersion_whenTheVersionDoesNotExist_throwsException() {
    when(credentialDataService.findByUuid(UUID_STRING))
        .thenReturn(null);

    try {
      subject.getCredentialVersion(userContext, new EventAuditRecordParameters(), UUID_STRING);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential_not_found"));
    }
  }

  @Test
  public void getCredentialVersion_whenTheUserLacksPermission_throwsException() {
    when(credentialDataService.findByUuid(UUID_STRING))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.getCredentialVersion(userContext, new EventAuditRecordParameters(), UUID_STRING);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential_not_found"));
    }
  }

  @Test
  public void getCredentialVersion_whenTheUserLacksPermission_setsCorrectAuditingParameters() {
    EventAuditRecordParameters auditRecordParameters = new EventAuditRecordParameters();

    when(credentialDataService.findByUuid(UUID_STRING))
        .thenReturn(version1);
    when(permissionService.hasCredentialReadPermission(userContext, CREDENTIAL_NAME))
        .thenReturn(false);

    try {
      subject.getCredentialVersion(userContext, auditRecordParameters, UUID_STRING);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(auditRecordParameters.getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParameters.getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    }
  }
}
