package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.SecretDataService;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class DecryptableDataDetectorTest {
  private SecretDataService secretDataService;
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  private DecryptableDataDetector decryptableDataDetector;

  {
    beforeEach(() -> {
      secretDataService = mock(SecretDataService.class);
      encryptionKeyCanaryMapper = mock(EncryptionKeyCanaryMapper.class);
    });

    describe("when no secrets could be decrypted", () -> {
      describe("when there are no secrets", () -> {
        beforeEach(() -> {
          when(secretDataService.count()).thenReturn(0L);
          when(secretDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
        });

        it("does not error", () -> {
          decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper, secretDataService);
          decryptableDataDetector.check();
        });
      });

      describe("when there are secrets", () -> {
        describe("when none can be decrypted", () -> {
          beforeEach(() -> {
            when(secretDataService.count()).thenReturn(4L);
            when(secretDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(0L);
          });

          itThrowsWithMessage("stuff", RuntimeException.class, "The encryption keys provided cannot decrypt any of the 4 value(s) in the database. Please make sure you've provided the necessary encryption keys.", () -> {
            decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper, secretDataService);
            decryptableDataDetector.check();
          });
        });

        describe("when some can be decrypted", () -> {
          beforeEach(() -> {
            when(secretDataService.count()).thenReturn(4L);
            when(secretDataService.countEncryptedWithKeyUuidIn(any())).thenReturn(1L);
          });

          it("does not error", () -> {
            decryptableDataDetector = new DecryptableDataDetector(encryptionKeyCanaryMapper, secretDataService);
            decryptableDataDetector.check();
          });
        });
      });
    });
  }
}
