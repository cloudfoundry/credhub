package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.config.LunaProviderProperties;
import io.pivotal.security.service.EncryptionService.CipherWrapper;
import org.junit.runner.RunWith;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

@RunWith(Spectrum.class)
public class LunaEncryptionServiceTest {
  private LunaEncryptionService subject;

  private Provider provider;
  private LunaConnection lunaConnection;
  private CipherWrapper exceptionThrowingCipher;
  private EncryptionKeysConfiguration encryptionKeysConfiguration;
  private LunaProviderProperties lunaProviderProperties;
  private ReentrantReadWriteLock.ReadLock readLock;
  private ReentrantReadWriteLock.WriteLock writeLock;
  private EncryptionKeyCanaryMapper keyMapper;
  private Key badKey;
  private Key goodKey;

  {
    beforeEach(() -> {
      keyMapper = mock(EncryptionKeyCanaryMapper.class);
      goodKey = mock(Key.class, "good key");
      badKey = mock(Key.class, "bad key");
      lunaProviderProperties = mock(LunaProviderProperties.class);
      when(lunaProviderProperties.getPartitionName()).thenReturn("expectedPartitionName");
      when(lunaProviderProperties.getPartitionPassword()).thenReturn("expectedPartitionPassword");
      encryptionKeysConfiguration = new EncryptionKeysConfiguration();
      provider = mock(Provider.class);
      when(provider.getName()).thenReturn("mock provider");
      lunaConnection = mock(LunaConnection.class);
      readLock = mock(ReentrantReadWriteLock.ReadLock.class);
      writeLock = mock(ReentrantReadWriteLock.WriteLock.class);
      when(lunaConnection.usageLock()).thenReturn(readLock);
      when(lunaConnection.reconnectLock()).thenReturn(writeLock);
    });

    describe("encryption and decryption when the Luna connection has been dropped", () -> {
      beforeEach(() -> {
        exceptionThrowingCipher = mock(CipherWrapper.class);

        subject = new LunaEncryptionService(keyMapper, lunaProviderProperties, lunaConnection) {
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
        when(lunaConnection.usageLock()).thenReturn(readLock);
        when(lunaConnection.reconnectLock()).thenReturn(writeLock);
      });

      describe("#encrypt", () -> {
        describe("when encrypt throws errors", () -> {
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

          it("unlocks after exception and locks again before encrypting", () -> {
            reset(writeLock);

            try {
              subject.encrypt(mock(Key.class), "a value");
            } catch (ProviderException e) {
              // expected
            }

            verify(readLock, times(2)).lock();
            verify(readLock, times(2)).unlock();

            verify(writeLock, times(1)).unlock();
            verify(writeLock, times(1)).lock();
          });

          it("creates new keys for UUIDs", () -> {
            verify(keyMapper).mapUuidsToKeys();
          });

          describe("when reconnect succeeds", () -> {
            beforeEach(() -> {
              simulateUuidMappingChangingFromBadToGood();
            });

            it("retries with a new key after reconnect", () -> {
              try {
                subject.encrypt(badKey, "some string");
              } catch (Exception e) {
                // expected
              }

              verify(exceptionThrowingCipher).init(anyInt(), eq(badKey), any(IvParameterSpec.class));
              verify(exceptionThrowingCipher).init(anyInt(), eq(goodKey), any(IvParameterSpec.class));
            });
          });
        });

        describe("encryption locks", () -> {
          it("acquires a Luna Usage readLock", () -> {
            reset(writeLock);

            subject.encrypt(mock(Key.class), "a value");
            verify(readLock, times(1)).lock();
            verify(readLock, times(1)).unlock();

            verify(writeLock, times(0)).unlock();
            verify(writeLock, times(0)).lock();
          });
        });
      });

      describe("#decrypt", () -> {
        describe("when decrypt throws errors", () -> {
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

          it("unlocks after exception and locks again before encrypting", () -> {
            reset(writeLock);

            try {
              subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
            } catch (IllegalBlockSizeException e) {
              // expected
            }

            verify(readLock, times(2)).lock();
            verify(readLock, times(2)).unlock();

            verify(writeLock, times(1)).lock();
            verify(writeLock, times(1)).unlock();
          });

          // no need to test this for encryption because the behavior is the same
          it("locks and unlocks the reconnect lock when login errors", () -> {
            reset(writeLock);
            doThrow(new RuntimeException()).when(
                lunaConnection).connect(any(String.class), any(String.class)
            );

            try {
              subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
            } catch (IllegalBlockSizeException | RuntimeException e) {
              // expected
            }

            verify(readLock, times(2)).lock();
            verify(readLock, times(2)).unlock();

            verify(writeLock, times(1)).lock();
            verify(writeLock, times(1)).unlock();
          });

          describe("when reconnect succeeds", () -> {
            beforeEach(() -> {
              simulateUuidMappingChangingFromBadToGood();
            });

            it("retries with a new key after reconnect", () -> {
              try {
                subject.decrypt(badKey, "some string".getBytes(), "some nonce".getBytes());
              } catch (Exception e) {
                // expected
              }

              verify(exceptionThrowingCipher).init(anyInt(), eq(badKey), any(IvParameterSpec.class));
              verify(exceptionThrowingCipher).init(anyInt(), eq(goodKey), any(IvParameterSpec.class));
            });
          });
        });

        describe("decryption locks", () -> {
          it("acquires a Luna Usage readLock", () -> {
            when(exceptionThrowingCipher.doFinal(any(byte[].class))).thenReturn("the result".getBytes());

            reset(writeLock);

            subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
            verify(readLock, times(1)).lock();
            verify(readLock, times(1)).unlock();

            verify(writeLock, times(0)).lock();
            verify(writeLock, times(0)).unlock();
          });
        });
      });
    });
  }

  private void simulateUuidMappingChangingFromBadToGood() {
    UUID uuidForChangingKeys = UUID.randomUUID();
    when(keyMapper.getUuidForKey(badKey)).thenReturn(uuidForChangingKeys);
    when(keyMapper.getKeyForUuid(uuidForChangingKeys)).thenReturn(goodKey);
  }
}
