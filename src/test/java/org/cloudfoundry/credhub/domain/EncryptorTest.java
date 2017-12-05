package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.service.InternalEncryptorConnection;
import org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper;
import org.cloudfoundry.credhub.service.InternalEncryptionService;
import org.cloudfoundry.credhub.service.RetryingEncryptionService;
import org.cloudfoundry.credhub.util.PasswordKeyProxyFactoryTestImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.Key;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class EncryptorTest {

  private EncryptionKeyCanaryMapper keyMapper;
  private Encryptor subject;

  private byte[] encryptedValue;

  private byte[] nonce;
  private UUID oldUuid;
  private UUID newUuid;

  @Before
  public void beforeEach() throws Exception {
    oldUuid = UUID.randomUUID();
    newUuid = UUID.randomUUID();

    keyMapper = mock(EncryptionKeyCanaryMapper.class);
    InternalEncryptionService internalEncryptionService;
    internalEncryptionService = new InternalEncryptionService(new PasswordKeyProxyFactoryTestImpl());

    Key newKey = new SecretKeySpec(parseHexBinary("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), 0, 16,
        "AES");
    when(keyMapper.getActiveKey()).thenReturn(newKey);
    when(keyMapper.getActiveUuid()).thenReturn(newUuid);
    Key oldKey = new SecretKeySpec(parseHexBinary("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0, 16,
        "AES");
    when(keyMapper.getKeyForUuid(oldUuid)).thenReturn(oldKey);
    when(keyMapper.getKeyForUuid(newUuid)).thenReturn(newKey);

    RetryingEncryptionService encryptionService = new RetryingEncryptionService(
        internalEncryptionService, keyMapper, new InternalEncryptorConnection());
    subject = new Encryptor(encryptionService);
  }

  @Test
  public void encrypt_returnsNullForNullInput() {
    EncryptedValue encryption = subject.encrypt(null);

    assertThat(encryption.getEncryptedValue(), nullValue());
    assertThat(encryption.getNonce(), nullValue());
  }

  @Test
  public void encrypt_encryptsPlainTest() {
    EncryptedValue encryption = subject.encrypt("some value");

    assertThat(encryption.getEncryptedValue(), notNullValue());
    assertThat(encryption.getNonce(), notNullValue());
  }

  @Test(expected = RuntimeException.class)
  public void encrypt_wrapsExceptions() {
    when(keyMapper.getActiveUuid()).thenThrow(new IllegalArgumentException());

    subject.encrypt("some value");
  }

  @Test
  public void decrypt_decryptsEncryptedValues() {
    EncryptedValue encryption = subject.encrypt("the expected clear text");
    encryptedValue = encryption.getEncryptedValue();
    nonce = encryption.getNonce();

    assertThat(subject.decrypt(new EncryptedValue(newUuid, encryptedValue, nonce)), equalTo("the expected clear text"));
  }

  @Test(expected = RuntimeException.class)
  public void decrypt_failsToEncryptWhenGivenWrongKeyUuid() {
    EncryptedValue encryption = subject.encrypt("the expected clear text");
    encryptedValue = encryption.getEncryptedValue();
    nonce = encryption.getNonce();

    subject.decrypt(new EncryptedValue(oldUuid, encryptedValue, nonce));
  }
}
