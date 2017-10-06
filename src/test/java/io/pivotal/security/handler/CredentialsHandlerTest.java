package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.SshCredentialVersion;
import io.pivotal.security.exceptions.EntryNotFoundException;
import io.pivotal.security.exceptions.InvalidQueryParameterException;
import io.pivotal.security.service.PermissionCheckingService;
import io.pivotal.security.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.request.PermissionOperation.DELETE;
import static io.pivotal.security.request.PermissionOperation.READ;
import static java.util.Collections.emptyList;
import static org.assertj.core.api.Java6Assertions.fail;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialsHandlerTest {
  private static final String CREDENTIAL_NAME = "/test/credential";
  private static final Instant VERSION1_CREATED_AT = Instant.ofEpochMilli(555555555);
  private static final Instant VERSION2_CREATED_AT = Instant.ofEpochMilli(777777777);
  private static final String UUID_STRING = "fake-uuid";
  private static final String USER = "darth-sirius";

  private CredentialsHandler subject;
  private PermissionedCredentialService permissionedCredentialService;
  private PermissionCheckingService permissionCheckingService;

  private UserContext userContext;
  private SshCredentialVersion version1;
  private SshCredentialVersion version2;

  @Before
  public void beforeEach() {
    Encryptor encryptor = mock(Encryptor.class);

    permissionedCredentialService = mock(PermissionedCredentialService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    subject = new CredentialsHandler(permissionedCredentialService, permissionCheckingService);

    userContext = mock(UserContext.class);
    when(userContext.getAclUser()).thenReturn(USER);

    version1 = new SshCredentialVersion(CREDENTIAL_NAME);
    version1.setVersionCreatedAt(VERSION1_CREATED_AT);
    version1.setEncryptor(encryptor);

    version2 = new SshCredentialVersion(CREDENTIAL_NAME);
    version2.setVersionCreatedAt(VERSION2_CREATED_AT);
    version2.setEncryptor(encryptor);
  }

  @Test
  public void deleteCredential_whenTheDeletionSucceeds_deletesTheCredential() {
    when(permissionedCredentialService.delete(any(), eq(CREDENTIAL_NAME))).thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, DELETE))
        .thenReturn(true);

    subject.deleteCredential(CREDENTIAL_NAME, userContext);

    verify(permissionedCredentialService, times(1)).delete(any(), eq(CREDENTIAL_NAME));
  }

  @Test
  public void deleteCredential_whenTheCredentialIsNotDeleted_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, DELETE))
        .thenReturn(true);
    when(permissionedCredentialService.delete(any(), eq(CREDENTIAL_NAME))).thenReturn(false);

    try {
      subject.deleteCredential(CREDENTIAL_NAME, userContext);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialExists_returnsADataResponse() {
    List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(permissionedCredentialService.findAllByName(any(UserContext.class), eq(CREDENTIAL_NAME)))
        .thenReturn(credentials);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    List<CredentialVersion> credentialVersionVersions = subject.getAllCredentialVersions(CREDENTIAL_NAME, userContext,
        newArrayList());

    assertThat(credentialVersionVersions, hasSize(2));
    assertThat(credentialVersionVersions.get(0).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersionVersions.get(0).getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    assertThat(credentialVersionVersions.get(1).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersionVersions.get(1).getVersionCreatedAt(), equalTo(VERSION2_CREATED_AT));
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialExists_setsCorrectAuditingParameters() {
    List<EventAuditRecordParameters> auditRecordParametersList = newArrayList();
    List<CredentialVersion> credentialVersions = newArrayList(version1);
    when(permissionedCredentialService.findAllByName(any(UserContext.class), eq(CREDENTIAL_NAME)))
        .thenReturn(credentialVersions);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    subject.getAllCredentialVersions(CREDENTIAL_NAME, userContext, auditRecordParametersList);

    assertThat(auditRecordParametersList, hasSize(1));
    assertThat(auditRecordParametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParametersList.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialDoesNotExist_throwsException() {
    when(permissionedCredentialService.findAllByName(any(UserContext.class), eq(CREDENTIAL_NAME)))
        .thenReturn(emptyList());
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    try {
      subject.getAllCredentialVersions(CREDENTIAL_NAME, userContext, newArrayList()
      );
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialDoesNotExist_setsCorrectAuditingParameter() {
    List<EventAuditRecordParameters> auditRecordParametersList = newArrayList();

    when(permissionedCredentialService.findAllByName(any(UserContext.class), eq(CREDENTIAL_NAME)))
        .thenReturn(emptyList());

    try {
      subject.getAllCredentialVersions(CREDENTIAL_NAME, userContext, auditRecordParametersList);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(auditRecordParametersList, hasSize(1));
      assertThat(auditRecordParametersList.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void getNCredentialVersions_whenTheNumberOfCredentialsIsNegative_throws() {
    List<EventAuditRecordParameters> auditRecordParametersList = newArrayList();

    when(permissionedCredentialService.findAllByName(any(UserContext.class), eq(CREDENTIAL_NAME)))
        .thenReturn(emptyList());

    try {
      subject.getNCredentialVersions(CREDENTIAL_NAME, -1, userContext, auditRecordParametersList);
      fail("should throw exception");
    } catch (InvalidQueryParameterException e) {
      assertThat(e.getInvalidQueryParameter(), equalTo("versions"));
      assertThat(e.getMessage(), equalTo("error.invalid_query_parameter"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialExists_returnsDataResponse() {
    when(permissionedCredentialService.findNByName(any(UserContext.class), eq(CREDENTIAL_NAME), eq(1)))
        .thenReturn(Arrays.asList(version1));
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    CredentialVersion credentialVersion = subject.getMostRecentCredentialVersion(
        CREDENTIAL_NAME, userContext,
        newArrayList()
    );

    assertThat(credentialVersion.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersion.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialExists_setsCorrectAuditingParameters() {
    List<EventAuditRecordParameters> auditRecordParametersList = newArrayList();
    when(permissionedCredentialService.findNByName(any(UserContext.class), eq(CREDENTIAL_NAME), eq(1)))
        .thenReturn(Arrays.asList(version1));
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(true);

    subject.getMostRecentCredentialVersion(CREDENTIAL_NAME, userContext, auditRecordParametersList);

    assertThat(auditRecordParametersList, hasSize(1));
    assertThat(auditRecordParametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
    assertThat(auditRecordParametersList.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialDoesNotExist_throwsException() {
    try {
      subject.getMostRecentCredentialVersion(CREDENTIAL_NAME, userContext, newArrayList());
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.getMostRecentCredentialVersion(CREDENTIAL_NAME, userContext, newArrayList());
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheUserLacksPermission_setsCorrectAuditingParameters() {
    List<EventAuditRecordParameters> auditRecordParametersList = newArrayList();

    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, READ))
        .thenReturn(false);

    try {
      subject.getMostRecentCredentialVersion(CREDENTIAL_NAME, userContext, auditRecordParametersList);
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(auditRecordParametersList.get(0).getCredentialName(), equalTo(CREDENTIAL_NAME));
      assertThat(auditRecordParametersList.get(0).getAuditingOperationCode(), equalTo(CREDENTIAL_ACCESS));
    }
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_returnsDataResponse() {
    when(permissionedCredentialService.findByUuid(eq(userContext), eq(UUID_STRING), any(List.class)))
        .thenReturn(version1);

    CredentialVersion credentialVersion = subject.getCredentialVersionByUUID(
        UUID_STRING,
        userContext,
        newArrayList()
    );
    assertThat(credentialVersion.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersion.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }
}
