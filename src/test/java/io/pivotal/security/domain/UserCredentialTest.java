package io.pivotal.security.domain;

import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.service.Encryption;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.UUID;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class UserCredentialTest {
  private UserCredential subject;
  private Encryptor encryptor;
  private final String CREDENTIAL_NAME = "/test/user";
  private final String USER_PASSWORD = "test-user-password";
  private final UUID ENCRYPTION_KEY_UUID = UUID.randomUUID();
  private final byte[] ENCRYPTED_PASSWORD = "encrypted-user-password".getBytes();
  private final byte[] NONCE = "user-NONCE".getBytes();
  private UserCredentialData userCredentialData;

  @Before
  public void beforeEach() {
    encryptor = mock(Encryptor.class);
  }

  @Test
  public void getCredentialType_returnsUser() {
    subject = new UserCredential();
    assertThat(subject.getCredentialType(), equalTo("user"));
  }

  @Test
  public void getUsername_returnsUsernameFromDelegate() {
    subject = new UserCredential(new UserCredentialData(CREDENTIAL_NAME).setUsername("test-user"));
    assertThat(subject.getUsername(), equalTo("test-user"));
  }

  @Test
  public void setUsername_setsUsernameOnDelegate() {
    UserCredentialData delegate = new UserCredentialData(CREDENTIAL_NAME);
    subject = new UserCredential(delegate);
    subject.setUsername("test-user");
    assertThat(delegate.getUsername(), equalTo("test-user"));
  }

  @Test
  public void getPassword_returnsDecryptedPassword_andOnlyDecryptsOnce() {
    final Encryption encryption = new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE);
    when(encryptor.decrypt(encryption))
        .thenReturn(USER_PASSWORD);
    userCredentialData = new UserCredentialData()
        .setEncryptedValue(ENCRYPTED_PASSWORD)
        .setNonce(NONCE)
        .setEncryptionKeyUuid(ENCRYPTION_KEY_UUID);
    subject = new UserCredential(userCredentialData)
        .setEncryptor(encryptor);

    String password = subject.getPassword();

    assertThat(password, equalTo(USER_PASSWORD));
    verify(encryptor, times(1)).decrypt(any());
  }

  @Test
  public void setPassword_encryptedProvidedPasswordOnce_andSetsCorrectValuesOnDelegate() {
    when(encryptor.encrypt(eq(USER_PASSWORD)))
        .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
    userCredentialData = new UserCredentialData(CREDENTIAL_NAME);
    subject = new UserCredential(userCredentialData)
        .setEncryptor(encryptor);

    subject.setPassword(USER_PASSWORD);

    verify(encryptor, times(1)).encrypt(eq(USER_PASSWORD));

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
  }

  @Test
  public void rotate_reEncryptsPasswordWithNewEncryptionKey() {
    UUID oldEncryptionKeyUuid = UUID.randomUUID();
    byte[] oldEncryptedPassword = "old-encrypted-password".getBytes();
    byte[] oldNonce = "old-nonce".getBytes();
    userCredentialData = new UserCredentialData(CREDENTIAL_NAME)
        .setEncryptionKeyUuid(oldEncryptionKeyUuid)
        .setEncryptedValue(oldEncryptedPassword)
        .setNonce(oldNonce);
    subject = new UserCredential(userCredentialData)
        .setEncryptor(encryptor);
    when(encryptor.decrypt(new Encryption(oldEncryptionKeyUuid, oldEncryptedPassword, oldNonce)))
        .thenReturn(USER_PASSWORD);
    when(encryptor.encrypt(eq(USER_PASSWORD)))
        .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));

    subject.rotate();

    verify(encryptor).decrypt(any());
    verify(encryptor).encrypt(USER_PASSWORD);

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
  }
}
