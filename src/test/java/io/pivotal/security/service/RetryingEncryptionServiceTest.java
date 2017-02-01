package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;
import org.mockito.InOrder;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Key;
import java.security.ProviderException;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.IllegalBlockSizeException;

@RunWith(Spectrum.class)
public class RetryingEncryptionServiceTest {
  private RetryingEncryptionService subject;

  private EncryptionKeyCanaryMapper keyMapper;
  private ReentrantReadWriteLock.ReadLock readLock;
  private ReentrantReadWriteLock.WriteLock writeLock;
  private Key firstKey;
  private Key secondKey;
  private EncryptionService encryptionService;
  private RemoteEncryptionConnectable remoteEncryptionConnectable;
  private UUID keyUuid;

  private ReentrantReadWriteLock readWriteLock;

  {
    beforeEach(() -> {
      keyMapper = mock(EncryptionKeyCanaryMapper.class);
      firstKey = mock(Key.class, "first key");
      secondKey = mock(Key.class, "second key");
      encryptionService = mock(EncryptionService.class);
      remoteEncryptionConnectable = mock(RemoteEncryptionConnectable.class);

      keyUuid = UUID.randomUUID();

      when(keyMapper.getUuidForKey(eq(firstKey))).thenReturn(keyUuid);
      when(keyMapper.getKeyForUuid(eq(keyUuid))).thenReturn(secondKey);

      subject = new RetryingEncryptionService(encryptionService, keyMapper, remoteEncryptionConnectable);

      final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
      readLock = spy(rwLock.readLock());
      writeLock = spy(rwLock.writeLock());
      readWriteLock = mock(ReentrantReadWriteLock.class);
      when(readWriteLock.readLock()).thenReturn(readLock);
      when(readWriteLock.writeLock()).thenReturn(writeLock);
      subject.readWriteLock = readWriteLock;
    });

    describe("#encrypt", () -> {
      describe("when encrypt throws errors", () -> {
        beforeEach(() -> {
          when(encryptionService.encrypt(any(Key.class), anyString()))
              .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
        });

        it("retries encryption failures", () -> {
          try {
            subject.encrypt(firstKey, "a value");
            fail("Expected exception");
          } catch (ProviderException e) {
            // expected
          }

          final InOrder inOrder = inOrder(encryptionService, remoteEncryptionConnectable);
          inOrder.verify(encryptionService).encrypt(eq(firstKey), anyString());
          inOrder.verify(remoteEncryptionConnectable).reconnect(any(ProviderException.class));
          inOrder.verify(encryptionService).encrypt(eq(secondKey), anyString());
        });

        it("unlocks after exception and locks again before encrypting", () -> {
          reset(writeLock);

          try {
            subject.encrypt(firstKey, "a value");
          } catch (ProviderException e) {
            // expected
          }

          verify(readLock, times(2)).lock();
          verify(readLock, times(2)).unlock();

          verify(writeLock, times(1)).unlock();
          verify(writeLock, times(1)).lock();
        });

        it("creates new keys for UUIDs", () -> {
          try {
            subject.encrypt(secondKey, "a value");
            fail("Expected exception");
          } catch (ProviderException e) {
            // expected
          }
          verify(keyMapper).mapUuidsToKeys();
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

      describe("using two threads", () -> {
        it("won't retry twice", () -> {
          final Object lock = new Object();
          final Key key = mock(Key.class);
          final Thread firstThread = new Thread("first") {
            @Override
            public void run() {
              try {
                subject.encrypt(key, "a value 1");
              } catch (Exception e) {
              }
            }
          };
          final Thread secondThread = new Thread("second") {
            @Override
            public void run() {
              try {
                subject.encrypt(key, "a value 2");
              } catch (Exception e) {
              }
            }
          };

          when(encryptionService.encrypt(any(Key.class), anyString()))
              .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
          // our first chance to capture the threads after they have triggered the exception
          // we want to ensure that both threads have triggered it before allowing either of them
          // to do a reconnect
          when(keyMapper.getUuidForKey(eq(key))).thenAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("first")) {
              secondThread.start();
              synchronized (lock) {
                lock.wait(); // pause the first thread
              }
            } else {
              synchronized (lock) {
                lock.notify(); // unpause the first thread
              }
            }

            return keyUuid;
          });

          firstThread.start();

          firstThread.join();
          secondThread.join();

          verify(keyMapper, times(1)).mapUuidsToKeys();
        });
      });
    });

    describe("#decrypt", () -> {
      describe("when decrypt throws errors", () -> {
        beforeEach(() -> {
          when(encryptionService.decrypt(any(Key.class), any(byte[].class), any(byte[].class)))
              .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
        });

        it("retries decryption failures", () -> {
          try {
            subject.decrypt(firstKey, "an encrypted value".getBytes(), "a nonce".getBytes());
            fail("Expected exception");
          } catch (ProviderException e) {
            // expected
          }

          final InOrder inOrder = inOrder(encryptionService, remoteEncryptionConnectable);
          inOrder.verify(encryptionService).decrypt(eq(firstKey), any(byte[].class), any(byte[].class));
          inOrder.verify(remoteEncryptionConnectable).reconnect(any(ProviderException.class));
          inOrder.verify(encryptionService).decrypt(eq(secondKey), any(byte[].class), any(byte[].class));
        });

        it("unlocks after exception and locks again before encrypting", () -> {
          reset(writeLock);

          try {
            subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
          } catch (ProviderException e) {
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
          doThrow(new RuntimeException()).when(remoteEncryptionConnectable).reconnect(any(Exception.class));

          try {
            subject.decrypt(firstKey, "an encrypted value".getBytes(), "a nonce".getBytes());
          } catch (IllegalBlockSizeException | RuntimeException e) {
            // expected
          }

          verify(readLock, times(2)).lock();
          verify(readLock, times(2)).unlock();

          verify(writeLock, times(1)).lock();
          verify(writeLock, times(1)).unlock();
        });
      });

      describe("decryption locks", () -> {
        it("acquires a Luna Usage readLock", () -> {
          when(encryptionService.decrypt(any(Key.class), any(byte[].class), any(byte[].class))).thenReturn("the result");

          reset(writeLock);

          subject.decrypt(mock(Key.class), "an encrypted value".getBytes(), "a nonce".getBytes());
          verify(readLock, times(1)).lock();
          verify(readLock, times(1)).unlock();

          verify(writeLock, times(0)).lock();
          verify(writeLock, times(0)).unlock();
        });
      });

      describe("using two threads", () -> {
        it("won't retry twice", () -> {
          final Object lock = new Object();
          final Key key = mock(Key.class);
          final Thread firstThread = new Thread("first") {
            @Override
            public void run() {
              try {
                subject.decrypt(key, "encrypted value 1".getBytes(), "nonce 1".getBytes());
              } catch (Exception e) {
              }
            }
          };
          final Thread secondThread = new Thread("second") {
            @Override
            public void run() {
              try {
                subject.decrypt(key, "encrypted value 2".getBytes(), "nonce 2".getBytes());
              } catch (Exception e) {
              }
            }
          };

          when(encryptionService.decrypt(any(Key.class), any(byte[].class), any(byte[].class)))
              .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
          // our first chance to capture the threads after they have triggered the exception
          // we want to ensure that both threads have triggered it before allowing either of them
          // to do a reconnect
          when(keyMapper.getUuidForKey(eq(key))).thenAnswer(invocation -> {
            if (Thread.currentThread().getName().equals("first")) {
              secondThread.start();
              synchronized (lock) {
                lock.wait(); // pause the first thread
              }
            } else {
              synchronized (lock) {
                lock.notify(); // unpause the first thread
              }
            }

            return keyUuid;
          });

          firstThread.start();

          firstThread.join();
          secondThread.join();

          verify(keyMapper, times(1)).mapUuidsToKeys();
        });
      });
    });
  }
}
