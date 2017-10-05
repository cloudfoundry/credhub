package io.pivotal.security.handler;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PermissionEntry;
import io.pivotal.security.service.PermissionService;
import io.pivotal.security.service.PermissionedCredentialService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static com.google.common.collect.Lists.newArrayList;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class RegenerateHandlerTest {
  private static final String SIGNER_NAME = "signer name";

  private RegenerateHandler subject;
  private CredentialDataService credentialDataService;
  private PermissionedCredentialService credentialService;
  private PermissionService permissionService;
  private UniversalCredentialGenerator credentialGenerator;
  private GenerationRequestGenerator generationRequestGenerator;
  private UserContext userContext;
  private PermissionEntry currentUserPermissionEntry;

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);
    credentialService = mock(PermissionedCredentialService.class);
    permissionService = mock(PermissionService.class);
    credentialGenerator = mock(UniversalCredentialGenerator.class);
    generationRequestGenerator = mock(GenerationRequestGenerator.class);
    currentUserPermissionEntry = mock(PermissionEntry.class);
    userContext = mock(UserContext.class);
    subject = new RegenerateHandler(
        credentialDataService,
        credentialService,
        permissionService,
        credentialGenerator,
        generationRequestGenerator);
  }

  @Test
  public void handleBulkRegenerate_regeneratesEverythingInTheList() throws Exception {
    when(credentialService.findAllCertificateCredentialsByCaName(userContext, SIGNER_NAME))
        .thenReturn(newArrayList("firstExpectedName", "secondExpectedName"));
    when(credentialDataService.findMostRecent(anyString()))
        .thenReturn(mock(Credential.class));
    PasswordGenerateRequest generateRequest1 = new PasswordGenerateRequest();
    generateRequest1.setName("firstExpectedName");
    PasswordGenerateRequest generateRequest2 = new PasswordGenerateRequest();
    generateRequest2.setName("secondExpectedName");
    when(generationRequestGenerator.createGenerateRequest(any(Credential.class)))
        .thenReturn(generateRequest1)
        .thenReturn(generateRequest2);

    subject.handleBulkRegenerate(SIGNER_NAME, userContext, currentUserPermissionEntry, newArrayList());

    verify(credentialService).save(
        eq("firstExpectedName"),
        any(), any(), any(),
        any(), anyBoolean(),
        eq(userContext),
        any(), any());
    verify(credentialService).save(
        eq("secondExpectedName"),
        any(), any(), any(),
        any(), anyBoolean(),
        eq(userContext),
        any(), any());
  }

}
