package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class DecryptableDataDetectorTest {

  private CredentialVersionDataService credentialVersionDataService;
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private DecryptableDataDetector decryptableDataDetector;

  @Before
  public void beforeEach() {
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
  }

  @Test
  public void whenNoCredentialsCouldBeDecrypted_whenThereAreNoCredentials_doesNotError() {
    when(credentialVersionDataService.count()).thenReturn(0L);
    when(credentialVersionDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
    decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper,
        credentialVersionDataService);
    decryptableDataDetector.check();
  }

  @Test
  public void whenNoCredentialsCouldBeDecrypted_whenThereAreCredentials_andNoneCanBeDecrypted() {
    when(credentialVersionDataService.count()).thenReturn(4L);
    when(credentialVersionDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
    decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper,
        credentialVersionDataService);
    try {
      decryptableDataDetector.check();
    } catch (RuntimeException rte) {
      assertThat(rte.getMessage(),
          containsString("The encryption keys provided cannot decrypt any of the 4 value(s) in the database."
              + " Please make sure you've provided the necessary encryption keys."));
    }
  }

  @Test
  public void whenCredentialsCanBeDecrypted_doesNotError() {
    when(credentialVersionDataService.count()).thenReturn(4L);
    when(credentialVersionDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(1L);
    decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper,
        credentialVersionDataService);
    decryptableDataDetector.check();
  }
}
