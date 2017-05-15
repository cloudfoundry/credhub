package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.credential.UserCredentialValue;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.PasswordSetRequest;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.request.UserSetRequest;
import io.pivotal.security.service.CredentialService;
import io.pivotal.security.view.CredentialView;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.ArrayList;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
public class SetRequestHandlerTest {

  @MockBean
  private CredentialService credentialService;

  private SetRequestHandler subject;

  private StringGenerationParameters generationParameters;
  private ArrayList<AccessControlEntry> accessControlEntries;
  private UserContext userContext;
  private AccessControlEntry currentEntry;

  @Before
  public void setUp() throws Exception {
    subject = new SetRequestHandler(credentialService);

    generationParameters = new StringGenerationParameters();
    accessControlEntries = new ArrayList<>();
    userContext = new UserContext();
    currentEntry = new AccessControlEntry();
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
}