package org.cloudfoundry.credhub.domain;

import java.util.UUID;

import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.services.RetryingEncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EncryptorTest {

  private Encryptor subject;
  private UUID oldUuid;
  private UUID newUuid;
  private RetryingEncryptionService encryptionService;

  @BeforeEach
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

  @Test
  public void encrypt_wrapsExceptions() throws Exception {
    when(encryptionService.encrypt(any())).thenThrow(new IllegalArgumentException());

    assertThrows(RuntimeException.class, () -> subject.encrypt("some value"));
  }

  @Test
  public void decrypt_decryptsEncryptedValues() throws Exception {
    final String expected = "the expected clear text";
    final EncryptedValue encryptedValue = new EncryptedValue(newUuid, "", "");
    when(encryptionService.decrypt(encryptedValue)).thenReturn(expected);
    final String result = subject.decrypt(encryptedValue);
    assertThat(result, equalTo(expected));
  }

  @Test
  public void decrypt_failsToEncryptWhenGivenWrongKeyUuid() throws Exception {
    final EncryptedValue knownKeyValue = new EncryptedValue(newUuid, new byte[]{}, new byte[]{});
    final EncryptedValue unknownKeyValue = new EncryptedValue(oldUuid, new byte[]{}, new byte[]{});

    when(encryptionService.decrypt(knownKeyValue)).thenReturn("decrypted");
    when(encryptionService.decrypt(unknownKeyValue)).thenThrow(new RuntimeException("key not found: " + oldUuid));

    assertThrows(RuntimeException.class, () -> subject.decrypt(new EncryptedValue(oldUuid, new byte[]{}, new byte[]{})));
  }
}
