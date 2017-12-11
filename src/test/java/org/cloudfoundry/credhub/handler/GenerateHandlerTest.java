package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.request.PasswordGenerateRequest;
import org.cloudfoundry.credhub.request.PermissionEntry;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.service.PermissionService;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.ArrayList;

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
    when(credentialService.save(anyObject(), anyObject(), anyObject(), anyList())).thenReturn(credentialVersion);
  }


  @Test
  public void handleGenerateRequest_whenPasswordGenerateRequest_passesCorrectParametersIncludingGeneration() {
    StringCredentialValue password = new StringCredentialValue("federation");
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    final ArrayList<EventAuditRecordParameters> eventAuditRecordParameters = new ArrayList<>();
    generateRequest.setType("password");
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setName("/captain");
    generateRequest.setAdditionalPermissions(accessControlEntries);
    generateRequest.setOverwrite(false);

    subject.handle(generateRequest, eventAuditRecordParameters);

    verify(credentialService).save(null, null, generateRequest, eventAuditRecordParameters);
    verify(permissionService).savePermissions(credentialVersion, accessControlEntries, eventAuditRecordParameters, true, "/captain");
  }
}
