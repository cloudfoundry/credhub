package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.SshCredentialVersion;
import org.cloudfoundry.credhub.exceptions.EntryNotFoundException;
import org.cloudfoundry.credhub.service.PermissionCheckingService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.cloudfoundry.credhub.view.CredentialView;
import org.cloudfoundry.credhub.view.DataResponse;
import org.cloudfoundry.credhub.request.PermissionOperation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;
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
  List<EventAuditRecordParameters> auditRecordParametersList;

  @Before
  public void beforeEach() {
    Encryptor encryptor = mock(Encryptor.class);

    permissionedCredentialService = mock(PermissionedCredentialService.class);
    permissionCheckingService = mock(PermissionCheckingService.class);
    subject = new CredentialsHandler(permissionedCredentialService);

    userContext = mock(UserContext.class);
    when(userContext.getActor()).thenReturn(USER);

    version1 = new SshCredentialVersion(CREDENTIAL_NAME);
    version1.setVersionCreatedAt(VERSION1_CREATED_AT);
    version1.setEncryptor(encryptor);

    version2 = new SshCredentialVersion(CREDENTIAL_NAME);
    version2.setVersionCreatedAt(VERSION2_CREATED_AT);
    version2.setEncryptor(encryptor);

  }

  @Test
  public void deleteCredential_whenTheDeletionSucceeds_deletesTheCredential() {
    when(permissionedCredentialService.delete(eq(CREDENTIAL_NAME), eq(auditRecordParametersList))).thenReturn(true);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
        .thenReturn(true);

    subject.deleteCredential(CREDENTIAL_NAME, auditRecordParametersList);

    verify(permissionedCredentialService, times(1)).delete(eq(CREDENTIAL_NAME), eq(auditRecordParametersList));
  }

  @Test
  public void deleteCredential_whenTheCredentialIsNotDeleted_throwsAnException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.DELETE))
        .thenReturn(true);
    when(permissionedCredentialService.delete(eq(CREDENTIAL_NAME), eq(auditRecordParametersList))).thenReturn(false);

    try {
      subject.deleteCredential(CREDENTIAL_NAME, auditRecordParametersList);
      fail("Should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialExists_returnsADataResponse() {
    List<CredentialVersion> credentials = newArrayList(version1, version2);
    when(permissionedCredentialService.findAllByName(eq(CREDENTIAL_NAME), eq(auditRecordParametersList)))
        .thenReturn(credentials);
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
        .thenReturn(true);

    DataResponse credentialVersions = subject.getAllCredentialVersions(CREDENTIAL_NAME, auditRecordParametersList);

    List<CredentialView> credentialViews = credentialVersions.getData();
    assertThat(credentialViews, hasSize(2));
    assertThat(credentialViews.get(0).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialViews.get(0).getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
    assertThat(credentialViews.get(1).getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialViews.get(1).getVersionCreatedAt(), equalTo(VERSION2_CREATED_AT));
  }

  @Test
  public void getAllCredentialVersions_whenTheCredentialDoesNotExist_throwsException() {
    when(permissionedCredentialService.findAllByName(eq(CREDENTIAL_NAME), eq(auditRecordParametersList)))
        .thenReturn(emptyList());
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
        .thenReturn(true);

    try {
      subject.getAllCredentialVersions(CREDENTIAL_NAME, auditRecordParametersList
      );
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialExists_returnsDataResponse() {
    when(permissionedCredentialService.findActiveByName(eq(CREDENTIAL_NAME), eq(auditRecordParametersList)))
        .thenReturn(Arrays.asList(version1));
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
        .thenReturn(true);

    DataResponse dataResponse = subject.getCurrentCredentialVersions(
        CREDENTIAL_NAME,
        auditRecordParametersList
    );
    CredentialView credentialView = dataResponse.getData().get(0);
    assertThat(credentialView.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialView.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheCredentialDoesNotExist_throwsException() {
    try {
      subject.getCurrentCredentialVersions(CREDENTIAL_NAME, newArrayList());
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getMostRecentCredentialVersion_whenTheUserLacksPermission_throwsException() {
    when(permissionCheckingService.hasPermission(USER, CREDENTIAL_NAME, PermissionOperation.READ))
        .thenReturn(false);

    try {
      subject.getCurrentCredentialVersions(CREDENTIAL_NAME, newArrayList());
      fail("should throw exception");
    } catch (EntryNotFoundException e) {
      assertThat(e.getMessage(), equalTo("error.credential.invalid_access"));
    }
  }

  @Test
  public void getCredentialVersion_whenTheVersionExists_returnsDataResponse() {
    when(permissionedCredentialService.findVersionByUuid(eq(UUID_STRING), any(List.class)))
        .thenReturn(version1);

    CredentialView credentialVersion = subject.getCredentialVersionByUUID(UUID_STRING, newArrayList());
    assertThat(credentialVersion.getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credentialVersion.getVersionCreatedAt(), equalTo(VERSION1_CREATED_AT));
  }
}
