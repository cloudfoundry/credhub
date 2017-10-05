package io.pivotal.security.domain;

import io.pivotal.security.entity.UserCredentialData;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.util.JsonObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.UUID;

import static org.hamcrest.Matchers.samePropertyValuesAs;
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
  private final byte[] ENCRYPTED_GENERATION_PARAMS = "encrypted-user-generation-params".getBytes();
  private final byte[] NONCE = "user-NONCE".getBytes();
  private final byte[] PARAMETERS_NONCE = "user-NONCE".getBytes();
  private final StringGenerationParameters STRING_GENERATION_PARAMS = new StringGenerationParameters().setUsername("not fnu").setExcludeLower(false);
  private final String USER_GENERATION_PARAMS_STRING = new JsonObjectMapper().writeValueAsString(STRING_GENERATION_PARAMS);
  private UserCredentialData userCredentialData;

  public UserCredentialTest() throws Exception {
  }

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
    byte[] oldEncryptedGenerationParams = "old-encrypted-generation-params".getBytes();

    byte[] oldNonce = "old-nonce".getBytes();
    byte[] oldParametersNonce = "old-parameters-nonce".getBytes();

    Encryption parametersEncryption = new Encryption(oldEncryptionKeyUuid, oldEncryptedGenerationParams, oldParametersNonce);

    userCredentialData = new UserCredentialData(CREDENTIAL_NAME)
        .setEncryptionKeyUuid(oldEncryptionKeyUuid)
        .setEncryptedValue(oldEncryptedPassword)
        .setEncryptedGenerationParameters(parametersEncryption)
        .setNonce(oldNonce);
    subject = new UserCredential(userCredentialData)
        .setEncryptor(encryptor);
    when(encryptor.decrypt(new Encryption(oldEncryptionKeyUuid, oldEncryptedPassword, oldNonce)))
        .thenReturn(USER_PASSWORD);
    when(encryptor.decrypt(new Encryption(oldEncryptionKeyUuid, oldEncryptedGenerationParams, oldParametersNonce)))
        .thenReturn(USER_GENERATION_PARAMS_STRING);

    when(encryptor.encrypt(eq(USER_PASSWORD)))
        .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
    when(encryptor.encrypt(eq(USER_GENERATION_PARAMS_STRING)))
        .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE));

    subject.rotate();

    verify(encryptor, times(2)).decrypt(any());
    verify(encryptor).encrypt(USER_PASSWORD);
    verify(encryptor).encrypt(USER_GENERATION_PARAMS_STRING);

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), equalTo(ENCRYPTED_GENERATION_PARAMS));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getNonce(), equalTo(PARAMETERS_NONCE));
  }

  @Test
  public void setGenerationParameters_setsEncryptedGenerationParametersAndNonce() {
    when(encryptor.encrypt(eq(USER_GENERATION_PARAMS_STRING)))
        .thenReturn(new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE));
    userCredentialData = new UserCredentialData(CREDENTIAL_NAME);
    subject = new UserCredential(userCredentialData)
        .setEncryptor(encryptor);

    subject.setGenerationParameters(STRING_GENERATION_PARAMS);

    verify(encryptor, times(1)).encrypt(eq(USER_GENERATION_PARAMS_STRING));

    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), equalTo(ENCRYPTED_GENERATION_PARAMS));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getNonce(), equalTo(PARAMETERS_NONCE));
  }

  @Test
  public void getGenerationParameters_decryptsGenerationParameters() {
    final Encryption encryption = new Encryption(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE);
    when(encryptor.decrypt(encryption))
        .thenReturn(USER_GENERATION_PARAMS_STRING);
    userCredentialData = new UserCredentialData()
        .setEncryptedGenerationParameters(encryption)

        .setEncryptionKeyUuid(ENCRYPTION_KEY_UUID);
    subject = new UserCredential(userCredentialData)
        .setEncryptor(encryptor);

    StringGenerationParameters generationParameters = subject.getGenerationParameters();

    assertThat(generationParameters, samePropertyValuesAs(STRING_GENERATION_PARAMS));
    verify(encryptor, times(1)).decrypt(any());
  }
}
