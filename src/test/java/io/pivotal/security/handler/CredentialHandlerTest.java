package io.pivotal.security.handler;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.exceptions.EntryNotFoundException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CredentialHandlerTest {
  private static final String CREDENTIAL_NAME = "/test/credential";

  private CredentialHandler subject;
  private CredentialDataService credentialDataService;

  @Before
  public void beforeEach() {
    credentialDataService = mock(CredentialDataService.class);
    subject = new CredentialHandler(credentialDataService);
  }

  @Test
  public void deleteCredential_whenTheDeletionSucceeds_deletesTheCredential() {
    when(credentialDataService.delete(CREDENTIAL_NAME)).thenReturn(true);

    subject.deleteCredential(CREDENTIAL_NAME);

    verify(credentialDataService, times(1)).delete(CREDENTIAL_NAME);
  }

  @Test(expected = EntryNotFoundException.class)
  public void deleteCredential_whenTheCredentialIsNotDeleted_throwsAnException() {
    when(credentialDataService.delete(CREDENTIAL_NAME)).thenReturn(false);

    subject.deleteCredential(CREDENTIAL_NAME);
  }
}
