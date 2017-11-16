package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextHolder;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.request.CertificateSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserSetRequest;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SetHandlerTest {
  private PermissionedCredentialService credentialService;
  private CertificateAuthorityService certificateAuthorityService;
  private PermissionService permissionService;

  private SetHandler subject;

  private StringGenerationParameters generationParameters;
  private ArrayList<PermissionEntry> accessControlEntries;
  private UserContext userContext;
  private CredentialVersion credentialVersion;

  @Before
  public void setUp() throws Exception {
    credentialService = mock(PermissionedCredentialService.class);
    certificateAuthorityService = mock(CertificateAuthorityService.class);
    permissionService = mock(PermissionService.class);

    userContext = new UserContext();
    UserContextHolder userContextHolder = new UserContextHolder();
    userContextHolder.setUserContext(userContext);
    subject = new SetHandler(credentialService, permissionService, certificateAuthorityService, userContextHolder);

    generationParameters = new StringGenerationParameters();
    accessControlEntries = new ArrayList<>();
    credentialVersion = mock(PasswordCredentialVersion.class);
    when(credentialService.save(anyObject(), anyString(), anyString(), anyObject(), anyObject(), anyList(), anyString(), anyList())).thenReturn(credentialVersion);
  }

  @Test
  public void handleSetRequest_whenOverwriteIsTrue_shouldSaveAccessControlEntries() {
    StringCredentialValue password = new StringCredentialValue("federation");
    PasswordSetRequest setRequest = new PasswordSetRequest();
    CredentialVersion existingCredMock = mock(CredentialVersion.class);

    when(credentialService.findMostRecent("/captain")).thenReturn(existingCredMock);
    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName("/captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(true);

    subject.handle(setRequest, eventAuditRecordParameters);

    verify(credentialService).save(
        existingCredMock, "/captain",
        "password",
        password,
        generationParameters,
        accessControlEntries,
        "overwrite",
        eventAuditRecordParameters
    );
    verify(permissionService).savePermissions(credentialVersion, accessControlEntries, eventAuditRecordParameters, false, "/captain");
  }


  @Test
  public void handleSetRequest_whenPasswordSetRequest_passesCorrectParametersIncludingGeneration() {
    StringCredentialValue password = new StringCredentialValue("federation");
    PasswordSetRequest setRequest = new PasswordSetRequest();

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName("/captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);

    subject.handle(setRequest, eventAuditRecordParameters);

    verify(credentialService).save(
        null, "/captain",
        "password",
        password,
        generationParameters,
        accessControlEntries,
        "no-overwrite",
        eventAuditRecordParameters
    );
    verify(permissionService).savePermissions(credentialVersion, accessControlEntries, eventAuditRecordParameters, true, "/captain");
  }

  @Test
  public void handleSetRequest_whenNonPasswordSetRequest_passesCorrectParametersWithNullGeneration() {
    UserSetRequest setRequest = new UserSetRequest();
    final UserCredentialValue userCredentialValue = new UserCredentialValue(
        "Picard",
        "Enterprise",
        "salt");

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("user");
    setRequest.setName("/captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);
    setRequest.setUserValue(userCredentialValue);

    subject.handle(setRequest, eventAuditRecordParameters);

    verify(credentialService).save(
        null, "/captain",
        "user",
        userCredentialValue,
        null,
        accessControlEntries,
        "no-overwrite",
        eventAuditRecordParameters
    );
    verify(permissionService).savePermissions(credentialVersion, accessControlEntries, eventAuditRecordParameters, true, "/captain");
  }

  @Test
  public void handleSetRequest_withACertificateSetRequest_andNoCaName_usesCorrectParameters() {
    CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue certificateValue = new CertificateCredentialValue(
        null,
        "Picard",
        "Enterprise",
        null);

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("certificate");
    setRequest.setName("/captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);
    setRequest.setCertificateValue(certificateValue);

    subject.handle(setRequest, eventAuditRecordParameters);

    verify(credentialService).save(
        null, "/captain",
        "certificate",
        certificateValue,
        null,
        accessControlEntries,
        "no-overwrite",
        eventAuditRecordParameters
    );
    verify(permissionService).savePermissions(credentialVersion, accessControlEntries, eventAuditRecordParameters, true, "/captain");
  }

  @Test
  public void handleSetRequest_withACertificateSetRequest_andACaName_providesCaCertificate() {
    CertificateCredentialValue cerificateAuthority = new CertificateCredentialValue(
        null,
        "test-ca-certificate",
        null,
        null
    );
    when(certificateAuthorityService.findActiveVersion("/test-ca-name"))
        .thenReturn(cerificateAuthority);

    CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue credentialValue = new CertificateCredentialValue(
        null,
        "Picard",
        "Enterprise",
        "test-ca-name");

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("certificate");
    setRequest.setName("/captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);
    setRequest.setCertificateValue(credentialValue);

    CertificateCredentialValue expectedCredentialValue = new CertificateCredentialValue(
        "test-ca-certificate",
        "Picard",
        "Enterprise",
        "test-ca-name"
    );
    ArgumentCaptor<CredentialValue> credentialValueArgumentCaptor = ArgumentCaptor.forClass(CredentialValue.class);

    subject.handle(setRequest, eventAuditRecordParameters);

    verify(credentialService).save(
        eq(null), eq("/captain"),
        eq("certificate"),
        credentialValueArgumentCaptor.capture(),
        eq(null),
        eq(accessControlEntries),
        eq("no-overwrite"),
        eq(eventAuditRecordParameters)
    );
    assertThat(credentialValueArgumentCaptor.getValue(), samePropertyValuesAs(expectedCredentialValue));
    verify(permissionService).savePermissions(credentialVersion, accessControlEntries, eventAuditRecordParameters, true, "/captain");
  }
}
