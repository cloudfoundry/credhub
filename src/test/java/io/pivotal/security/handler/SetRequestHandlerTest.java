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
import io.pivotal.security.service.CredentialService;
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
public class SetRequestHandlerTest {
  private CredentialService credentialService;
  private CertificateAuthorityService certificateAuthorityService;

  private SetRequestHandler subject;

  private StringGenerationParameters generationParameters;
  private ArrayList<PermissionEntry> accessControlEntries;
  private UserContext userContext;
  private PermissionEntry currentEntry;

  @Before
  public void setUp() throws Exception {
    credentialService = mock(CredentialService.class);
    certificateAuthorityService = mock(CertificateAuthorityService.class);

    subject = new SetRequestHandler(credentialService, certificateAuthorityService);

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
        userContext,
        eventAuditRecordParameters,
        "government",
        false,
        "password",
        generationParameters,
        password,
        accessControlEntries,
        currentEntry))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            userContext,
            eventAuditRecordParameters,
            setRequest,
            currentEntry);

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
        userContext,
        eventAuditRecordParameters,
        "captain",
        false,
        "user",
        null,
        userCredentialValue,
        accessControlEntries,
        currentEntry))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            userContext,
            eventAuditRecordParameters,
            setRequest,
            currentEntry);

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
        userContext,
        eventAuditRecordParameters,
        "captain",
        false,
        "certificate",
        null,
        certificateValue,
        accessControlEntries,
        currentEntry))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            userContext,
            eventAuditRecordParameters,
            setRequest,
            currentEntry);

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
    when(certificateAuthorityService.findMostRecent("test-ca-name"))
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
        eq(userContext),
        eq(eventAuditRecordParameters),
        eq("captain"),
        eq(false),
        eq("certificate"),
        eq(null),
        any(),
        eq(accessControlEntries),
        eq(currentEntry)
    ))
        .thenReturn(credentialView);

    final CredentialView returnValue = subject
        .handle(
            userContext,
            eventAuditRecordParameters,
            setRequest,
            currentEntry);

    assertThat(returnValue, equalTo(credentialView));

    verify(credentialService).save(
        eq(userContext),
        eq(eventAuditRecordParameters),
        eq("captain"),
        eq(false),
        eq("certificate"),
        eq(null),
        credentialValueArgumentCaptor.capture(),
        eq(accessControlEntries),
        eq(currentEntry)
    );
    assertThat(credentialValueArgumentCaptor.getValue(), samePropertyValuesAs(expectedCredentialValue));
  }
}
