package org.cloudfoundry.credhub.services;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DefaultDecryptableDataDetectorTest {

  private static CredentialVersionDataService credentialVersionDataService;
  private static EncryptionKeySet keySet;
  private DecryptableDataDetector decryptableDataDetector;

  @BeforeAll
  public static void beforeEach() {
    credentialVersionDataService = mock(CredentialVersionDataService.class);
    keySet = new EncryptionKeySet();
  }

  @Test
  public void whenNoCredentialsCouldBeDecrypted_whenThereAreNoCredentials_doesNotError() {
    when(credentialVersionDataService.count()).thenReturn(0L);
    when(credentialVersionDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
    decryptableDataDetector = new DefaultDecryptableDataDetector(
      keySet,
      credentialVersionDataService
    );
    decryptableDataDetector.check();
  }

  @Test
  public void whenNoCredentialsCouldBeDecrypted_whenThereAreCredentials_andNoneCanBeDecrypted() {
    when(credentialVersionDataService.count()).thenReturn(4L);
    when(credentialVersionDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
    decryptableDataDetector = new DefaultDecryptableDataDetector(
      keySet,
      credentialVersionDataService
    );
    try {
      decryptableDataDetector.check();
    } catch (final RuntimeException rte) {
      assertThat(rte.getMessage(),
        containsString("The encryption keys provided cannot decrypt any of the 4 value(s) in the database."
          + " Please make sure you've provided the necessary encryption keys."));
    }
  }

  @Test
  public void whenCredentialsCanBeDecrypted_doesNotError() {
    when(credentialVersionDataService.count()).thenReturn(4L);
    when(credentialVersionDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(1L);
    decryptableDataDetector = new DefaultDecryptableDataDetector(
      keySet,
      credentialVersionDataService
    );
    decryptableDataDetector.check();
  }
}
