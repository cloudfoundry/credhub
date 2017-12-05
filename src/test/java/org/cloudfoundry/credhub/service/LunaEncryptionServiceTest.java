package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.util.TimedRetry;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.function.Supplier;
import javax.crypto.SecretKey;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class LunaEncryptionServiceTest {

  private LunaEncryptionService subject;
  private LunaConnection connection;
  private SecretKey aesKey;
  private TimedRetry timedRetry;

  @Before
  @SuppressWarnings("Duplicates")
  public void setUp() throws Exception {
    connection = mock(LunaConnection.class);
    aesKey = mock(SecretKey.class);
    when(connection.generateKey()).thenReturn(aesKey);
    when(connection.getKey("fake_key_name")).thenReturn(aesKey);

    timedRetry = mock(TimedRetry.class);
    when(timedRetry.retryEverySecondUntil(anyLong(), any(Supplier.class))).thenAnswer(answer -> {
      Supplier<Boolean> retryingOperation = answer.getArgumentAt(1, Supplier.class);
      for(int i=0; i < 10; i++) {
        if(retryingOperation.get()) {
          return true;
        }
      }
      return false;
    });
  }

  @Test
  public void createKeyProxy_createsKeyIfNoKeyExists() throws Exception {
    setupNoKeyExists();

    EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionKeyName("fake_key_name");

    subject = new LunaEncryptionService(connection, true, timedRetry);

    assertThat(subject.createKeyProxy(keyMetadata).getKey(), equalTo(aesKey));
    verify(connection).setKeyEntry("fake_key_name", aesKey);
  }

  @Test
  public void createKeyProxy_getsKeyIfKeyExists() throws Exception {
    setupKeyExists();

    EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionKeyName("fake_key_name");

    subject = new LunaEncryptionService(connection, true, timedRetry);

    assertThat(subject.createKeyProxy(keyMetadata).getKey(), equalTo(aesKey));
    verify(connection, never()).setKeyEntry("fake_key_name", aesKey);
  }

  @Test
  public void createKeyProxy_waitsForKeyIfCreationIsDisabled() throws Exception {
    setupAnotherProcessCreatesKey();

    EncryptionKeyMetadata keyMetadata = new EncryptionKeyMetadata();
    keyMetadata.setEncryptionKeyName("fake_key_name");

    subject = new LunaEncryptionService(connection, false, timedRetry);

    assertThat(subject.createKeyProxy(keyMetadata).getKey(), equalTo(aesKey));
    verify(connection, never()).generateKey();
  }

  private void setupNoKeyExists() throws Exception {
    when(connection.containsAlias("fake_key_name")).thenReturn(false);
  }

  private void setupAnotherProcessCreatesKey() throws Exception {
    when(connection.containsAlias("fake_key_name"))
        .thenReturn(false)
        .thenReturn(true);
  }

  private void setupKeyExists() throws Exception {
    when(connection.containsAlias("fake_key_name")).thenReturn(true);
  }
}
