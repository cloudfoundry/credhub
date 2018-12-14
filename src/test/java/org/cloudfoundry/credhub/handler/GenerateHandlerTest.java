package org.cloudfoundry.credhub.handler;

import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.request.PasswordGenerateRequest;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

@RunWith(JUnit4.class)
public class GenerateHandlerTest {
  private PermissionedCredentialService credentialService;
  private UniversalCredentialGenerator universalCredentialGenerator;

  private GenerateHandler subject;

  private StringGenerationParameters generationParameters;

  @Mock
  private CEFAuditRecord cefAuditRecord;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    credentialService = mock(PermissionedCredentialService.class);
    universalCredentialGenerator = mock(UniversalCredentialGenerator.class);

    subject = new GenerateHandler(credentialService, universalCredentialGenerator, cefAuditRecord);

    generationParameters = new StringGenerationParameters();
    CredentialVersion credentialVersion = mock(PasswordCredentialVersion.class);
    when(credentialVersion.getCredential()).thenReturn(mock(Credential.class));
    when(credentialService.save(any(), any(), any())).thenReturn(credentialVersion);
  }


  @Test
  public void handleGenerateRequest_whenPasswordGenerateRequest_passesCorrectParametersIncludingGeneration() {
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setType("password");
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setName("/captain");
    generateRequest.setOverwrite(false);

    subject.handle(generateRequest);

    verify(credentialService).save(null, null, generateRequest);
  }

  @Test
  public void handleGenerateRequest_addsToCEFAuditRecord() {
    PasswordGenerateRequest generateRequest = new PasswordGenerateRequest();

    generateRequest.setType("password");
    generateRequest.setGenerationParameters(generationParameters);
    generateRequest.setName("/captain");
    generateRequest.setOverwrite(false);

    subject.handle(generateRequest);
    verify(cefAuditRecord, times(1)).setVersion(any(CredentialVersion.class));
    verify(cefAuditRecord, times(1)).setResource(any(Credential.class));
  }
}
