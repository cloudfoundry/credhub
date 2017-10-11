package io.pivotal.security.handler;

import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.StringCredentialValue;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;

import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyList;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class GenerateHandlerTest {
  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator universalCredentialGenerator;
  private PermissionService permissionService;

  private GenerateHandler subject;

  private StringGenerationParameters generationParameters;
  private ArrayList<PermissionEntry> accessControlEntries;
  private UserContext userContext;
  private CredentialVersion credentialVersion;

  @Before
  public void setUp() throws Exception {
    credentialService = mock(PermissionedCredentialService.class);
    universalCredentialGenerator = mock(UniversalCredentialGenerator.class);
    permissionService = mock(PermissionService.class);

    subject = new GenerateHandler(credentialService, permissionService, universalCredentialGenerator);

    generationParameters = new StringGenerationParameters();
    accessControlEntries = new ArrayList<>();
    userContext = new UserContext();
    credentialVersion = mock(PasswordCredentialVersion.class);
    when(credentialService.save(anyObject(), anyString(), anyString(), anyObject(), anyObject(), anyList(), anyBoolean(), anyObject(), anyList())).thenReturn(credentialVersion);
  }


  @Test
  public void handleGenerateRequest_whenPasswordGenerateRequest_passesCorrectParametersIncludingGeneration() {
    StringCredentialValue password = new StringCredentialValue("federation");
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    generateRequest.setType("password");
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setName("captain");
    generateRequest.setAdditionalPermissions(accessControlEntries);
    generateRequest.setOverwrite(false);

    subject.handle(generateRequest, userContext, eventAuditRecordParameters);

    verify(credentialService).save(
        null, "captain",
        "password",
        null,
        generationParameters,
        accessControlEntries,
        false,
        userContext,
        eventAuditRecordParameters
    );
    verify(permissionService).saveAccessControlEntries(userContext, credentialVersion, accessControlEntries, eventAuditRecordParameters, true, "captain");
  }
}
