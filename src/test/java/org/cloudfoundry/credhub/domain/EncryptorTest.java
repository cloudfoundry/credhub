package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.RetryingEncryptionService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Matchers.any;
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

    subject = new Encryptor(encryptionService);
  }

  @Test
  public void encrypt_returnsNullForNullInput() {
    EncryptedValue encryption = subject.encrypt(null);

    assertThat(encryption.getEncryptedValue(), nullValue());
    assertThat(encryption.getNonce(), nullValue());
  }

  @Test
  public void encrypt_encryptsPlainTest() throws Exception {
    String value = "some value";
    EncryptedValue encrypted = mock(EncryptedValue.class);
    when(encryptionService.encrypt(value)).thenReturn(encrypted);

    EncryptedValue result = subject.encrypt("some value");
    assertThat(result, equalTo(encrypted));
  }

  @Test(expected = RuntimeException.class)
  public void encrypt_wrapsExceptions() throws Exception {
    when(encryptionService.encrypt(any())).thenThrow(new IllegalArgumentException());

    subject.encrypt("some value");
  }

  @Test
  public void decrypt_decryptsEncryptedValues() throws Exception {
    String expected = "the expected clear text";
    EncryptedValue encryptedValue = new EncryptedValue(newUuid, "", "");
    when(encryptionService.decrypt(encryptedValue)).thenReturn(expected);
    String result = subject.decrypt(encryptedValue);
    assertThat(result, equalTo(expected));
  }

  @Test(expected = RuntimeException.class)
  public void decrypt_failsToEncryptWhenGivenWrongKeyUuid() {
    EncryptedValue encryption = subject.encrypt("the expected clear text");
    encryptedValue = encryption.getEncryptedValue();
    nonce = encryption.getNonce();

    subject.decrypt(new EncryptedValue(oldUuid, encryptedValue, nonce));
  }
}
