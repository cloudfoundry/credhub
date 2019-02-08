package org.cloudfoundry.credhub.domain;

import java.util.UUID;

import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.services.RetryingEncryptionService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class EncryptorTest {

  private Encryptor subject;

  private byte[] encryptedValue;

  private byte[] nonce;
  private UUID oldUuid;
  private UUID newUuid;
  private RetryingEncryptionService encryptionService;

  @Before
  public void beforeEach() throws Exception {
    oldUuid = UUID.randomUUID();
    newUuid = UUID.randomUUID();

    encryptionService = mock(RetryingEncryptionService.class);

    subject = new DefaultEncryptor(encryptionService);
  }

  @Test
  public void encrypt_returnsNullForNullInput() {
    final EncryptedValue encryption = subject.encrypt(null);

    assertThat(encryption.getEncryptedValue(), nullValue());
    assertThat(encryption.getNonce(), nullValue());
  }

  @Test
  public void encrypt_encryptsPlainTest() throws Exception {
    final String value = "some value";
    final EncryptedValue encrypted = mock(EncryptedValue.class);
    when(encryptionService.encrypt(value)).thenReturn(encrypted);

    final EncryptedValue result = subject.encrypt("some value");
    assertThat(result, equalTo(encrypted));
  }

  @Test(expected = RuntimeException.class)
  public void encrypt_wrapsExceptions() throws Exception {
    when(encryptionService.encrypt(any())).thenThrow(new IllegalArgumentException());

    subject.encrypt("some value");
  }

  @Test
  public void decrypt_decryptsEncryptedValues() throws Exception {
    final String expected = "the expected clear text";
    final EncryptedValue encryptedValue = new EncryptedValue(newUuid, "", "");
    when(encryptionService.decrypt(encryptedValue)).thenReturn(expected);
    final String result = subject.decrypt(encryptedValue);
    assertThat(result, equalTo(expected));
  }

  @Test(expected = RuntimeException.class)
  public void decrypt_failsToEncryptWhenGivenWrongKeyUuid() {
    final EncryptedValue encryption = subject.encrypt("the expected clear text");
    encryptedValue = encryption.getEncryptedValue();
    nonce = encryption.getNonce();

    subject.decrypt(new EncryptedValue(oldUuid, encryptedValue, nonce));
  }
}
