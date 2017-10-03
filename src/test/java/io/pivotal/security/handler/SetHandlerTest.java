package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.credential.CredentialValue;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.request.CertificateSetRequest;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserSetRequest;
import io.pivotal.security.service.PermissionedCredentialService;
import io.pivotal.security.view.CredentialView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SetHandlerTest {
  private PermissionedCredentialService credentialService;
  private CertificateAuthorityService certificateAuthorityService;

  private SetHandler subject;

  private StringGenerationParameters generationParameters;
  private ArrayList<PermissionEntry> accessControlEntries;
  private UserContext userContext;
  private PermissionEntry currentEntry;

  @Before
  public void setUp() throws Exception {
    credentialService = mock(PermissionedCredentialService.class);
    certificateAuthorityService = mock(CertificateAuthorityService.class);

    subject = new SetHandler(credentialService, certificateAuthorityService);

    generationParameters = new StringGenerationParameters();
    accessControlEntries = new ArrayList<>();
    userContext = new UserContext();
    currentEntry = new PermissionEntry();
  }

  @Test
  public void handleSetRequest_whenPasswordSetRequest_passesInCorrectParametersIncludingGeneration() {
    StringCredentialValue password = new StringCredentialValue("federation");
    PasswordSetRequest setRequest = new PasswordSetRequest();

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("password");
    setRequest.setGenerationParameters(generationParameters);
    setRequest.setPassword(password);
    setRequest.setName("government");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);

    CredentialView credentialView = mock(CredentialView.class);

    when(credentialService.save(
        "government",
        "password",
        password,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        currentEntry,
        eventAuditRecordParameters
    ))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            setRequest,
            userContext,
            currentEntry,
            eventAuditRecordParameters
        );

    assertThat(returnValue, equalTo(credentialView));
  }

  @Test
  public void handleSetRequest_whenNonPasswordSetRequest_passesInCorrectParametersWithNullGeneration() {
    UserSetRequest setRequest = new UserSetRequest();
    final UserCredentialValue userCredentialValue = new UserCredentialValue(
        "Picard",
        "Enterprise",
        "salt");

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("user");
    setRequest.setName("captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);
    setRequest.setUserValue(userCredentialValue);

    CredentialView credentialView = mock(CredentialView.class);

    when(credentialService.save(
        "captain",
        "user",
        userCredentialValue,
        null,
        accessControlEntries,
        false,
        userContext,
        currentEntry,
        eventAuditRecordParameters
    ))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            setRequest,
            userContext,
            currentEntry,
            eventAuditRecordParameters
        );

    assertThat(returnValue, equalTo(credentialView));
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
    setRequest.setName("captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);
    setRequest.setCertificateValue(certificateValue);

    CredentialView credentialView = mock(CredentialView.class);

    when(credentialService.save(
        "captain",
        "certificate",
        certificateValue,
        null,
        accessControlEntries,
        false,
        userContext,
        currentEntry,
        eventAuditRecordParameters
    ))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            setRequest,
            userContext,
            currentEntry,
            eventAuditRecordParameters
        );

    assertThat(returnValue, equalTo(credentialView));
  }

  @Test
  public void handleSetRequest_withACertificateSetRequest_andACaName_providesCaCertificate() {
    CertificateCredentialValue cerificateAuthority = new CertificateCredentialValue(
        null,
        "test-ca-certificate",
        null,
        null
    );
    when(certificateAuthorityService.findMostRecent(userContext, "test-ca-name"))
        .thenReturn(cerificateAuthority);

    CertificateSetRequest setRequest = new CertificateSetRequest();
    final CertificateCredentialValue credentialValue = new CertificateCredentialValue(
        null,
        "Picard",
        "Enterprise",
        "test-ca-name");

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    setRequest.setType("certificate");
    setRequest.setName("captain");
    setRequest.setAdditionalPermissions(accessControlEntries);
    setRequest.setOverwrite(false);
    setRequest.setCertificateValue(credentialValue);

    CredentialView credentialView = mock(CredentialView.class);

    CertificateCredentialValue expectedCredentialValue = new CertificateCredentialValue(
        "test-ca-certificate",
        "Picard",
        "Enterprise",
        "test-ca-name"
    );
    ArgumentCaptor<CredentialValue> credentialValueArgumentCaptor = ArgumentCaptor.forClass(CredentialValue.class);

    when(credentialService.save(
        eq("captain"),
        eq("certificate"),
        any(),
        eq(null),
        eq(accessControlEntries),
        eq(false),
        eq(userContext),
        eq(currentEntry),
        eq(eventAuditRecordParameters)
    ))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            setRequest,
            userContext,
            currentEntry,
            eventAuditRecordParameters
        );

    assertThat(returnValue, equalTo(credentialView));

    verify(credentialService).save(
        eq("captain"),
        eq("certificate"),
        credentialValueArgumentCaptor.capture(),
        eq(null),
        eq(accessControlEntries),
        eq(false),
        eq(userContext),
        eq(currentEntry),
        eq(eventAuditRecordParameters)
    );
    assertThat(credentialValueArgumentCaptor.getValue(), samePropertyValuesAs(expectedCredentialValue));
  }
}
