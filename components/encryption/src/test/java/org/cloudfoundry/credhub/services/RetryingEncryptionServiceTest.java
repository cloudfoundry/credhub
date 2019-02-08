package org.cloudfoundry.credhub.services;

import java.security.ProviderException;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.IllegalBlockSizeException;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.exceptions.KeyNotFoundException;
import org.cloudfoundry.credhub.utils.StringUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InOrder;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class RetryingEncryptionServiceTest {

  private RetryingEncryptionService subject;

  private ReentrantReadWriteLock.ReadLock readLock;
  private ReentrantReadWriteLock.WriteLock writeLock;
  private InternalEncryptionService encryptionService;
  private UUID activeKeyUuid;

  private ReentrantReadWriteLock readWriteLock;
  private EncryptionKeySet keySet;
  private EncryptionKey firstActiveKey;
  private EncryptionKey secondActiveKey;

  @Before
  public void beforeEach() {
    keySet = mock(EncryptionKeySet.class);
    encryptionService = mock(LunaEncryptionService.class);

    activeKeyUuid = UUID.randomUUID();
    firstActiveKey = mock(EncryptionKey.class);
    secondActiveKey = mock(EncryptionKey.class);

    subject = new RetryingEncryptionService(keySet);

    final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();
    readLock = spy(rwLock.readLock());
    writeLock = spy(rwLock.writeLock());
    readWriteLock = spy(ReentrantReadWriteLock.class);
    when(readWriteLock.readLock()).thenReturn(readLock);
    when(readWriteLock.writeLock()).thenReturn(writeLock);
    subject.readWriteLock = readWriteLock;
  }

  @Test
  public void encrypt_shouldEncryptTheStringWithoutAttemptingToReconnect() throws Exception {

    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    final EncryptedValue expectedEncryption = mock(EncryptedValue.class);
    when(firstActiveKey.encrypt("fake-plaintext"))
      .thenReturn(expectedEncryption);

    final EncryptedValue encryptedValue = subject.encrypt("fake-plaintext");

    assertThat(encryptedValue, equalTo(expectedEncryption));

    verify(encryptionService, times(0))
      .reconnect(any(IllegalBlockSizeException.class));
    verify(keySet, times(0)).reload();
  }

  @Test
  public void encrypt_whenThrowsAnError_retriesEncryptionFailure() throws Exception {

    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    when(firstActiveKey.encrypt("a value"))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));

    when(firstActiveKey.getProvider()).thenReturn(encryptionService);

    try {
      subject.encrypt("a value");
      fail("Expected exception");
    } catch (final ProviderException e) {
      // expected
    }

    final InOrder inOrder = inOrder(firstActiveKey, encryptionService);
    inOrder.verify(firstActiveKey).encrypt(anyString());
    inOrder.verify(encryptionService).reconnect(any(ProviderException.class));
    inOrder.verify(firstActiveKey).encrypt(anyString());
  }

  @Test
  public void encrypt_whenThrowsAnError_unlocksAfterExceptionAndLocksAgainBeforeEncrypting() throws Exception {
    when(keySet.getActive())
      .thenReturn(firstActiveKey);


    when(firstActiveKey.encrypt("a value"))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
    reset(writeLock);

    try {
      subject.encrypt("a value");
    } catch (final ProviderException e) {
      // expected
    }

    verify(readLock, times(2)).lock();
    verify(readLock, times(2)).unlock();

    verify(writeLock, times(1)).unlock();
    verify(writeLock, times(1)).lock();
  }

  @Test
  public void encryption_whenThrowsAnError_createsNewKeysForUUIDs() throws Exception {
    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    when(firstActiveKey.encrypt(anyString()))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));

    when(firstActiveKey.getProvider()).thenReturn(encryptionService);

    try {
      subject.encrypt("a value");
      fail("Expected exception");
    } catch (final ProviderException e) {
      // expected
    }
    verify(keySet).reload();
  }

  @Test
  public void encryption_whenTheOperationSucceedsOnlyAfterReconnection_shouldReturnTheEncryptedString()
    throws Exception {
    final EncryptedValue expectedEncryption = mock(EncryptedValue.class);

    when(keySet.getActive())
      .thenReturn(firstActiveKey)
      .thenReturn(secondActiveKey);

    when(firstActiveKey.encrypt("fake-plaintext"))
      .thenThrow(new IllegalBlockSizeException("test exception"));
    when(firstActiveKey.getProvider()).thenReturn(encryptionService);
    when(secondActiveKey.encrypt("fake-plaintext"))
      .thenReturn(expectedEncryption);
    when(secondActiveKey.getProvider()).thenReturn(encryptionService);

    assertThat(subject.encrypt("fake-plaintext"), equalTo(expectedEncryption));


    verify(encryptionService, times(1))
      .reconnect(any(IllegalBlockSizeException.class));
    verify(keySet, times(1)).reload();
  }

  @Test
  public void encryption_encryptionLocks_acquiresALunaUsageReadLock() throws Exception {
    reset(writeLock);

    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    subject.encrypt("a value");
    verify(readLock, times(1)).lock();
    verify(readLock, times(1)).unlock();

    verify(writeLock, times(0)).unlock();
    verify(writeLock, times(0)).lock();
  }

  @Test
  public void whenUsingTwoThreads_wontRetryTwice() throws Exception {
    final Object lock = new Object();
    final Thread firstThread = new Thread("first") {
      @Override
      public void run() {
        try {
          subject.encrypt("a value 1");
        } catch (final Exception e) {
          //do nothing
        }
      }
    };
    final Thread secondThread = new Thread("second") {
      @Override
      public void run() {
        try {
          subject.encrypt("a value 2");
        } catch (final Exception e) {
          //do nothing
        }
      }
    };

    subject = new RacingRetryingEncryptionServiceForTest(firstThread, secondThread, lock);
    when(keySet.getActive())
      .thenReturn(firstActiveKey);
    when(firstActiveKey.encrypt(anyString()))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
    when(firstActiveKey.getProvider()).thenReturn(encryptionService);

    firstThread.start();

    firstThread.join();
    secondThread.join();

    verify(keySet, times(1)).reload();
  }

  @Test
  public void decrypt_shouldReturnTheDecryptedStringWithoutAttemptionToReconnect() throws Exception {

    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey);
    when(firstActiveKey.decrypt("fake-encrypted-value".getBytes(StringUtil.UTF_8), "fake-nonce".getBytes(StringUtil.UTF_8)))
      .thenReturn("fake-plaintext");


    assertThat(
      subject.decrypt(new EncryptedValue(activeKeyUuid, "fake-encrypted-value".getBytes(StringUtil.UTF_8), "fake-nonce".getBytes(StringUtil.UTF_8))),
      equalTo("fake-plaintext"));

    verify(encryptionService, times(0)).reconnect(any(IllegalBlockSizeException.class));
    verify(keySet, times(0)).reload();
  }

  @Test
  public void decrypt_whenThrowsAnError_retriesDecryptionFailure() throws Exception {

    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey);

    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    when(firstActiveKey.decrypt(any(byte[].class), any(byte[].class)))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));

    when(firstActiveKey.getProvider()).thenReturn(encryptionService);

    try {
      subject.decrypt(new EncryptedValue(activeKeyUuid, "an encrypted value".getBytes(StringUtil.UTF_8), "a nonce".getBytes(StringUtil.UTF_8)));
      fail("Expected exception");
    } catch (final ProviderException e) {
      // expected
    }

    final InOrder inOrder = inOrder(firstActiveKey, encryptionService);
    inOrder.verify(firstActiveKey).decrypt(any(byte[].class), any(byte[].class));
    inOrder.verify(encryptionService).reconnect(any(ProviderException.class));
    inOrder.verify(firstActiveKey)
      .decrypt(any(byte[].class), any(byte[].class));
  }

  @Test
  public void decrypt_whenThrowsErrors_unlocksAfterExceptionAndLocksAgainBeforeEncrypting() throws Exception {

    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey);


    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    when(firstActiveKey.decrypt(any(byte[].class), any(byte[].class)))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
    reset(writeLock);

    try {
      subject.decrypt(new EncryptedValue(activeKeyUuid, "an encrypted value".getBytes(StringUtil.UTF_8), "a nonce".getBytes(StringUtil.UTF_8)));
    } catch (final ProviderException e) {
      // expected
    }

    verify(readLock, times(2)).lock();
    verify(readLock, times(2)).unlock();

    verify(writeLock, times(1)).lock();
    verify(writeLock, times(1)).unlock();
  }

  @Test
  public void decrypt_locksAndUnlocksTheReconnectLockWhenLoginError() throws Exception {
    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey);

    when(firstActiveKey.decrypt(any(byte[].class), any(byte[].class)))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));
    reset(writeLock);
    doThrow(new RuntimeException()).when(encryptionService)
      .reconnect(any(Exception.class));

    try {
      subject.decrypt(new EncryptedValue(activeKeyUuid, "an encrypted value".getBytes(StringUtil.UTF_8), "a nonce".getBytes(StringUtil.UTF_8)));
    } catch (final IllegalBlockSizeException | RuntimeException e) {
      // expected
    }

    verify(readLock, times(2)).lock();
    verify(readLock, times(2)).unlock();

    verify(writeLock, times(1)).lock();
    verify(writeLock, times(1)).unlock();
  }

  @Test
  public void decrypt_whenTheOperationSucceedsOnlyAfterReconnection() throws Exception {

    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey)
      .thenReturn(secondActiveKey);

    when(keySet.getActive())
      .thenReturn(firstActiveKey);

    when(firstActiveKey
      .decrypt("fake-encrypted-value".getBytes(StringUtil.UTF_8), "fake-nonce".getBytes(StringUtil.UTF_8)))
      .thenThrow(new IllegalBlockSizeException("test exception"));
    when(firstActiveKey.getProvider()).thenReturn(encryptionService);

    when(secondActiveKey
      .decrypt("fake-encrypted-value".getBytes(StringUtil.UTF_8), "fake-nonce".getBytes(StringUtil.UTF_8)))
      .thenReturn("fake-plaintext");
    when(secondActiveKey.getProvider()).thenReturn(encryptionService);

    assertThat(subject
        .decrypt(new EncryptedValue(activeKeyUuid, "fake-encrypted-value".getBytes(StringUtil.UTF_8), "fake-nonce".getBytes(StringUtil.UTF_8))),
      equalTo("fake-plaintext"));

    verify(encryptionService, times(1))
      .reconnect(any(IllegalBlockSizeException.class));
    verify(keySet, times(1)).reload();
  }

  @Test(expected = KeyNotFoundException.class)
  public void decrypt_whenTheEncryptionKeyCannotBeFound_throwsAnException() throws Exception {
    final UUID fakeUuid = UUID.randomUUID();
    reset(encryptionService);
    when(keySet.get(fakeUuid)).thenReturn(null);
    subject.decrypt(new EncryptedValue(fakeUuid, "something we cant read".getBytes(StringUtil.UTF_8), "nonce".getBytes(StringUtil.UTF_8)));
  }

  @Test
  public void decryptionLocks_acquiresALunaUsageReadLock() throws Exception {

    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey);

    subject.decrypt(new EncryptedValue(activeKeyUuid, "an encrypted value".getBytes(StringUtil.UTF_8), "a nonce".getBytes(StringUtil.UTF_8)));
    verify(readLock, times(1)).lock();
    verify(readLock, times(1)).unlock();

    verify(writeLock, times(0)).lock();
    verify(writeLock, times(0)).unlock();
  }

  @Test
  public void usingTwoThread_wontRetryTwice() throws Exception {
    final Object lock = new Object();
    final Thread firstThread = new Thread("first") {
      @SuppressFBWarnings(
        value = "DE_MIGHT_IGNORE",
        justification = "Exception is a no-op in this test"
      )
      @Override
      public void run() {
        try {
          subject.decrypt(new EncryptedValue(activeKeyUuid, "a value 1".getBytes(StringUtil.UTF_8), "nonce".getBytes(StringUtil.UTF_8)));
        } catch (final Exception e) {
          //do nothing
        }
      }
    };
    final Thread secondThread = new Thread("second") {
      @SuppressFBWarnings(
        value = "DE_MIGHT_IGNORE",
        justification = "Exception is a no-op in this test"
      )
      @Override
      public void run() {
        try {
          subject.decrypt(new EncryptedValue(activeKeyUuid, "a value 2".getBytes(StringUtil.UTF_8), "nonce".getBytes(StringUtil.UTF_8)));
        } catch (final Exception e) {
          //do nothing
        }
      }
    };

    subject = new RacingRetryingEncryptionServiceForTest(firstThread, secondThread, lock);

    when(keySet.get(activeKeyUuid))
      .thenReturn(firstActiveKey);

    when(keySet.getActive())
      .thenReturn(firstActiveKey);


    when(firstActiveKey.decrypt(any(byte[].class), any(byte[].class)))
      .thenThrow(new ProviderException("function 'C_GenerateRandom' returns 0x30"));

    when(firstActiveKey.getProvider()).thenReturn(encryptionService);

    firstThread.start();

    firstThread.join();
    secondThread.join();

    verify(keySet, times(1)).reload();
  }

  private class RacingRetryingEncryptionServiceForTest extends RetryingEncryptionService {

    private final Thread firstThread;
    private final Thread secondThread;
    private final Object lock;

    RacingRetryingEncryptionServiceForTest(final Thread firstThread, final Thread secondThread, final Object lock) {
      super(RetryingEncryptionServiceTest.this.keySet);
      this.firstThread = firstThread;
      this.secondThread = secondThread;
      this.lock = lock;
    }

    @SuppressFBWarnings(
      value = {
        "UW_UNCOND_WAIT",
        "WA_NOT_IN_LOOP",
        "REC_CATCH_EXCEPTION",
      },
      justification = "We want to force the first thread to wait, and we don't care about exceptions."
    )
    @Override
    public void setNeedsReconnectFlag() {
      try {
        if (Thread.currentThread().equals(firstThread)) {
          secondThread.start();
          synchronized (lock) {
            lock.wait(); // pause the first thread
          }
          Thread.sleep(10); // give thread two a chance to get all the way through the retry
        } else {
          synchronized (lock) {
            lock.notify(); // unpause the first thread
          }
        }
      } catch (final Exception e) {
        //do nothing
      }
      /* give thread one a chance to set the needsRetry flag
      after thread two finishes. sets us up for reconnecting twice */
      super.setNeedsReconnectFlag();
    }
  }
}

