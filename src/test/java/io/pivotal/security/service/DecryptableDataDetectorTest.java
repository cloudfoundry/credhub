package io.pivotal.security.service;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.CredentialDataService;
import org.junit.runner.RunWith;

@RunWith(Spectrum.class)
public class DecryptableDataDetectorTest {

  private CredentialDataService credentialDataService;
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private DecryptableDataDetector decryptableDataDetector;

  {
    beforeEach(() -> {
      credentialDataService = mock(CredentialDataService.class);
      encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    });

    describe("when no secrets could be decrypted", () -> {
      describe("when there are no secrets", () -> {
        beforeEach(() -> {
          when(credentialDataService.count()).thenReturn(0L);
          when(credentialDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
        });

        it("does not error", () -> {
          decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper,
              credentialDataService);
          decryptableDataDetector.check();
        });
      });

      describe("when there are secrets", () -> {
        describe("when none can be decrypted", () -> {
          beforeEach(() -> {
            when(credentialDataService.count()).thenReturn(4L);
            when(credentialDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
          });

          itThrowsWithMessage("stuff", RuntimeException.class,
              "The encryption keys provided cannot decrypt any of the 4 value(s) in the database."
                  + " Please make sure you've provided the necessary encryption keys.",
              () -> {
                decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper,
                    credentialDataService);
                decryptableDataDetector.check();
              });
        });

        describe("when some can be decrypted", () -> {
          beforeEach(() -> {
            when(credentialDataService.count()).thenReturn(4L);
            when(credentialDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(1L);
          });

          it("does not error", () -> {
            decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper,
                credentialDataService);
            decryptableDataDetector.check();
          });
        });
      });
    });
  }
}
