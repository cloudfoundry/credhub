package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.config.LunaProviderProperties;
import io.pivotal.security.service.EncryptionService.CipherWrapper;
import org.junit.runner.RunWith;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class LunaEncryptionServiceTest {
  private LunaEncryptionService subject;

  private Provider provider;
  private LunaConnection lunaConnection;
  private CipherWrapper exceptionThrowingCipher;
  private EncryptionKeysConfiguration encryptionKeysConfiguration;
  private LunaProviderProperties lunaProviderProperties;

  {
    beforeEach(() -> {
      lunaProviderProperties = mock(LunaProviderProperties.class);
      when(lunaProviderProperties.getPartitionName()).thenReturn("expectedPartitionName");
      when(lunaProviderProperties.getPartitionPassword()).thenReturn("expectedPartitionPassword");
      encryptionKeysConfiguration = new EncryptionKeysConfiguration();
      provider = mock(Provider.class);
      when(provider.getName()).thenReturn("mock provider");
      lunaConnection = mock(LunaConnection.class);
    });

    describe("encryption and decryption when the Luna connection has been dropped", () -> {
      beforeEach(() -> {
        exceptionThrowingCipher = mock(CipherWrapper.class);

        subject = new LunaEncryptionService(encryptionKeysConfiguration, lunaProviderProperties, lunaConnection) {
          @Override
          public CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
            return exceptionThrowingCipher;
          }
          @Override
          public SecureRandom getSecureRandom() {
            return new SecureRandom();
          }
        };
        reset(lunaConnection);
      });

      describe("#encrypt", () -> {
        beforeEach(() -> {
          when(exceptionThrowingCipher.doFinal(any(byte[].class)))
              .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
        });

        it("retries encryption failures", () -> {
          try {
            subject.encrypt(mock(Key.class), "a value");
            fail("Expected exception");
          } catch (ProviderException e) {
            // expected
          }

          verify(exceptionThrowingCipher, times(2)).doFinal(any(byte[].class));
          verify(lunaConnection).connect("expectedPartitionName", "expectedPartitionPassword");
        });
      });

      describe("#decrypt", () -> {
        beforeEach(() -> {
          when(exceptionThrowingCipher.doFinal(any(byte[].class)))
              .thenThrow(new IllegalBlockSizeException("Could not process input data: function 'C_Decrypt' returns 0x30"));
        });

        it("retries decryption failures", () -> {
          try {
            subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
            fail("Expected exception");
          } catch (IllegalBlockSizeException e) {
            // expected
          }

          verify(exceptionThrowingCipher, times(2)).doFinal(any(byte[].class));
          verify(lunaConnection).connect("expectedPartitionName", "expectedPartitionPassword");
        });
      });

    });
  }
}
