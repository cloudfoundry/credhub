package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.service.EncryptionService.CipherWrapper;
import org.junit.runner.RunWith;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class LunaEncryptionServiceTest {
  private LunaEncryptionService subject;

  private Provider provider;
  private LunaEncryptionService.LunaSlotManagerProxy lunaSlotManager;
  private CipherWrapper exceptionThrowingCipher;

  {
    beforeEach(() -> {
      provider = mock(Provider.class);
      when(provider.getName()).thenReturn("mock provider");
      lunaSlotManager = mock(LunaEncryptionService.LunaSlotManagerProxy.class);
      exceptionThrowingCipher = mock(CipherWrapper.class);
      when(exceptionThrowingCipher.doFinal(any(byte[].class)))
          .thenThrow(new IllegalBlockSizeException("Could not process input data: function 'C_Decrypt' returns 0x30"));
    });

    describe("encrypton and decryption when the Luna connection has been dropped", () -> {
      beforeEach(() -> {
        // this subject is only suitable for testing the retry behavior
        subject = new LunaEncryptionService(provider, lunaSlotManager) {
          @Override
          public CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
            return exceptionThrowingCipher;
          }
          @Override
          public SecureRandom getSecureRandom() {
            return new SecureRandom();
          }
          @Override
          protected void initializeKeys() throws Exception {
            login();
          }
        };
      });

      it("retries encryption failures", () -> {
        try {
          subject.encrypt(mock(Key.class), "a value");
          fail("Expected exception");
        } catch (IllegalBlockSizeException e) {
          // expected
        }

        verify(exceptionThrowingCipher, times(2)).doFinal(any(byte[].class));
        verify(lunaSlotManager).reinitialize();
        verify(lunaSlotManager).login(anyString(), anyString());
      });

      it("retries decryption failures", () -> {
        try {
          subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
          fail("Expected exception");
        } catch (IllegalBlockSizeException e) {
          // expected
        }

        verify(exceptionThrowingCipher, times(2)).doFinal(any(byte[].class));
        verify(lunaSlotManager).reinitialize();
        verify(lunaSlotManager).login(anyString(), anyString());
      });

    });
  }
}
