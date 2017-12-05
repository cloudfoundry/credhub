package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.JsonObjectMapper;
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
public class UserCredentialVersionTest {
  private UserCredentialVersion subject;
  private Encryptor encryptor;
  private final String CREDENTIAL_NAME = "/test/user";
  private final String USER_PASSWORD = "test-user-password";
  private final UUID ENCRYPTION_KEY_UUID = UUID.randomUUID();
  private final byte[] ENCRYPTED_PASSWORD = "encrypted-user-password".getBytes();
  private final byte[] ENCRYPTED_GENERATION_PARAMS = "encrypted-user-generation-params".getBytes();
  private final byte[] NONCE = "user-NONCE".getBytes();
  private final byte[] PARAMETERS_NONCE = "user-NONCE".getBytes();
  private final StringGenerationParameters STRING_GENERATION_PARAMS = new StringGenerationParameters().setUsername("not fnu").setExcludeLower(false).setLength(USER_PASSWORD.length());
  private final String USER_GENERATION_PARAMS_STRING = new JsonObjectMapper().writeValueAsString(STRING_GENERATION_PARAMS);
  private UserCredentialVersionData userCredentialData;

  public UserCredentialVersionTest() throws Exception {
  }

  @Before
  public void beforeEach() {
    encryptor = mock(Encryptor.class);
  }

  @Test
  public void getCredentialType_returnsUser() {
    subject = new UserCredentialVersion();
    assertThat(subject.getCredentialType(), equalTo("user"));
  }

  @Test
  public void getUsername_returnsUsernameFromDelegate() {
    subject = new UserCredentialVersion(new UserCredentialVersionData(CREDENTIAL_NAME).setUsername("test-user"));
    assertThat(subject.getUsername(), equalTo("test-user"));
  }

  @Test
  public void setUsername_setsUsernameOnDelegate() {
    UserCredentialVersionData delegate = new UserCredentialVersionData(CREDENTIAL_NAME);
    subject = new UserCredentialVersion(delegate);
    subject.setUsername("test-user");
    assertThat(delegate.getUsername(), equalTo("test-user"));
  }

  @Test
  public void getPassword_returnsDecryptedPassword_andOnlyDecryptsOnce() {
    final EncryptedValue encryption = new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE);
    when(encryptor.decrypt(encryption))
        .thenReturn(USER_PASSWORD);
    userCredentialData = new UserCredentialVersionData()
        .setEncryptedValueData(new EncryptedValue()
        .setEncryptedValue(ENCRYPTED_PASSWORD)
        .setNonce(NONCE)
        .setEncryptionKeyUuid(ENCRYPTION_KEY_UUID));
    subject = new UserCredentialVersion(userCredentialData)
        .setEncryptor(encryptor);

    String password = subject.getPassword();

    assertThat(password, equalTo(USER_PASSWORD));
    verify(encryptor, times(1)).decrypt(any());
  }

  @Test
  public void setPassword_encryptedProvidedPasswordOnce_andSetsCorrectValuesOnDelegate() {
    when(encryptor.encrypt(eq(USER_PASSWORD)))
        .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
    userCredentialData = new UserCredentialVersionData(CREDENTIAL_NAME);
    subject = new UserCredentialVersion(userCredentialData)
        .setEncryptor(encryptor);

    subject.setPassword(USER_PASSWORD);

    verify(encryptor, times(1)).encrypt(eq(USER_PASSWORD));

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValueData().getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
  }

  @Test
  public void rotate_reEncryptsPasswordWithNewEncryptionKey() {
    UUID oldEncryptionKeyUuid = UUID.randomUUID();
    byte[] oldEncryptedPassword = "old-encrypted-password".getBytes();
    byte[] oldEncryptedGenerationParams = "old-encrypted-generation-params".getBytes();

    byte[] oldNonce = "old-nonce".getBytes();
    byte[] oldParametersNonce = "old-parameters-nonce".getBytes();

    EncryptedValue parametersEncryption = new EncryptedValue(oldEncryptionKeyUuid, oldEncryptedGenerationParams, oldParametersNonce);

    EncryptedValue encryptedUserValue = new EncryptedValue()
        .setEncryptionKeyUuid(oldEncryptionKeyUuid)
        .setEncryptedValue(oldEncryptedPassword)
        .setNonce(oldNonce);
    userCredentialData = new UserCredentialVersionData(CREDENTIAL_NAME)
        .setEncryptedValueData(encryptedUserValue)
        .setEncryptedGenerationParameters(parametersEncryption);
    subject = new UserCredentialVersion(userCredentialData)
        .setEncryptor(encryptor);
    when(encryptor.decrypt(new EncryptedValue(oldEncryptionKeyUuid, oldEncryptedPassword, oldNonce)))
        .thenReturn(USER_PASSWORD);
    when(encryptor.decrypt(new EncryptedValue(oldEncryptionKeyUuid, oldEncryptedGenerationParams, oldParametersNonce)))
        .thenReturn(USER_GENERATION_PARAMS_STRING);

    when(encryptor.encrypt(eq(USER_PASSWORD)))
        .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
    when(encryptor.encrypt(eq(USER_GENERATION_PARAMS_STRING)))
        .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE));

    subject.rotate();

    verify(encryptor, times(2)).decrypt(any());
    verify(encryptor).encrypt(USER_PASSWORD);
    verify(encryptor).encrypt(USER_GENERATION_PARAMS_STRING);

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValueData().getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), equalTo(ENCRYPTED_GENERATION_PARAMS));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getNonce(), equalTo(PARAMETERS_NONCE));
  }

  @Test
  public void setGenerationParameters_setsEncryptedGenerationParametersAndNonce() {
    when(encryptor.encrypt(eq(USER_GENERATION_PARAMS_STRING)))
        .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE));
    userCredentialData = new UserCredentialVersionData(CREDENTIAL_NAME);
    subject = new UserCredentialVersion(userCredentialData)
        .setEncryptor(encryptor);

    subject.setGenerationParameters(STRING_GENERATION_PARAMS);

    verify(encryptor, times(1)).encrypt(eq(USER_GENERATION_PARAMS_STRING));

    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), equalTo(ENCRYPTED_GENERATION_PARAMS));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getNonce(), equalTo(PARAMETERS_NONCE));
  }

  @Test
  public void getGenerationParameters_decryptsGenerationParameters() {
    final EncryptedValue parameterEncryption = new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE);
    final EncryptedValue passwordEncryption = new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE);
    when(encryptor.decrypt(parameterEncryption))
        .thenReturn(USER_GENERATION_PARAMS_STRING);
    when(encryptor.decrypt(passwordEncryption))
        .thenReturn(USER_PASSWORD);
    userCredentialData = new UserCredentialVersionData()
        .setEncryptedValueData(passwordEncryption)
        .setEncryptedGenerationParameters(parameterEncryption);
    subject = new UserCredentialVersion(userCredentialData)
        .setEncryptor(encryptor);

    StringGenerationParameters generationParameters = subject.getGenerationParameters();

    assertThat(generationParameters, samePropertyValuesAs(STRING_GENERATION_PARAMS));
    verify(encryptor, times(2)).decrypt(any());
  }

  @Test
  public void getGenerationParameters_returnsNullIfTheGenerationParametersAreNull() {
    userCredentialData = new UserCredentialVersionData();
    subject = new UserCredentialVersion(userCredentialData)
        .setEncryptor(encryptor);
    subject.setGenerationParameters(null);

    StringGenerationParameters generationParameters = subject.getGenerationParameters();

    assertThat(generationParameters, equalTo(null));
  }
}
