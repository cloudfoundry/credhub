package org.cloudfoundry.credhub.domain;

import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.UserCredentialVersionData;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
@SuppressFBWarnings(
  value = "SS_SHOULD_BE_STATIC",
  justification = "Test files generally don't need static fields."
)
public class UserCredentialVersionTest {
  private final String CREDENTIAL_NAME = "/test/user";
  private final String USER_PASSWORD = "test-user-password";
  private final UUID ENCRYPTION_KEY_UUID = UUID.randomUUID();
  private final byte[] ENCRYPTED_PASSWORD = "encrypted-user-password".getBytes(UTF_8);
  private final byte[] ENCRYPTED_GENERATION_PARAMS = "encrypted-user-generation-params".getBytes(UTF_8);
  private final byte[] NONCE = "user-NONCE".getBytes(UTF_8);
  private final byte[] PARAMETERS_NONCE = "user-NONCE".getBytes(UTF_8);
  private StringGenerationParameters stringGenerationParameters;
  private String userGenerationParametersString;
  private UserCredentialVersion subject;
  private Encryptor encryptor;
  private UserCredentialVersionData userCredentialData;

  public UserCredentialVersionTest() throws Exception {
    super();
  }

  @Before
  public void beforeEach() throws JsonProcessingException {
    encryptor = mock(Encryptor.class);

     stringGenerationParameters = new StringGenerationParameters();
     stringGenerationParameters.setUsername("not fnu");
     stringGenerationParameters.setExcludeLower(false);
     stringGenerationParameters.setLength(USER_PASSWORD.length());

     userGenerationParametersString = new JsonObjectMapper().writeValueAsString(stringGenerationParameters);
  }

  @Test
  public void getCredentialType_returnsUser() {
    subject = new UserCredentialVersion("test cred");
    assertThat(subject.getCredentialType(), equalTo("user"));
  }

  @Test
  public void getUsername_returnsUsernameFromDelegate() {

    final UserCredentialVersionData userCredentialVersionData = new UserCredentialVersionData(CREDENTIAL_NAME);
    userCredentialVersionData.setUsername("test-user");

    subject = new UserCredentialVersion(userCredentialVersionData);
    assertThat(subject.getUsername(), equalTo("test-user"));
  }

  @Test
  public void setUsername_setsUsernameOnDelegate() {
    final UserCredentialVersionData delegate = new UserCredentialVersionData(CREDENTIAL_NAME);
    subject = new UserCredentialVersion(delegate);
    subject.setUsername("test-user");
    assertThat(delegate.getUsername(), equalTo("test-user"));
  }

  @Test
  public void getPassword_returnsDecryptedPassword_andOnlyDecryptsOnce() {
    final EncryptedValue encryption = new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE);
    when(encryptor.decrypt(encryption))
      .thenReturn(USER_PASSWORD);

    final EncryptedValue encryptedValue = new EncryptedValue();
    encryptedValue.setEncryptedValue(ENCRYPTED_PASSWORD);
    encryptedValue.setNonce(NONCE);
    encryptedValue.setEncryptionKeyUuid(ENCRYPTION_KEY_UUID);

    userCredentialData = new UserCredentialVersionData();
    userCredentialData.setEncryptedValueData(encryptedValue);

    subject = new UserCredentialVersion(userCredentialData);
    subject.setEncryptor(encryptor);

    final String password = subject.getPassword();

    assertThat(password, equalTo(USER_PASSWORD));
    verify(encryptor, times(1)).decrypt(any());
  }

  @Test
  public void setPassword_encryptedProvidedPasswordOnce_andSetsCorrectValuesOnDelegate() {
    when(encryptor.encrypt(eq(USER_PASSWORD)))
      .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
    userCredentialData = new UserCredentialVersionData(CREDENTIAL_NAME);
    subject = new UserCredentialVersion(userCredentialData);
    subject.setEncryptor(encryptor);

    subject.setPassword(USER_PASSWORD);

    verify(encryptor, times(1)).encrypt(eq(USER_PASSWORD));

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValueData().getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
  }

  @Test
  public void rotate_reEncryptsPasswordWithNewEncryptionKey() {
    final UUID oldEncryptionKeyUuid = UUID.randomUUID();
    final byte[] oldEncryptedPassword = "old-encrypted-password".getBytes(UTF_8);
    final byte[] oldEncryptedGenerationParams = "old-encrypted-generation-params".getBytes(UTF_8);

    final byte[] oldNonce = "old-nonce".getBytes(UTF_8);
    final byte[] oldParametersNonce = "old-parameters-nonce".getBytes(UTF_8);

    final EncryptedValue parametersEncryption = new EncryptedValue(oldEncryptionKeyUuid, oldEncryptedGenerationParams, oldParametersNonce);

    final EncryptedValue encryptedUserValue = new EncryptedValue();
    encryptedUserValue.setEncryptionKeyUuid(oldEncryptionKeyUuid);
    encryptedUserValue.setEncryptedValue(oldEncryptedPassword);
    encryptedUserValue.setNonce(oldNonce);

    userCredentialData = new UserCredentialVersionData(CREDENTIAL_NAME);
    userCredentialData.setEncryptedValueData(encryptedUserValue);
    userCredentialData.setEncryptedGenerationParameters(parametersEncryption);

    subject = new UserCredentialVersion(userCredentialData);
    subject.setEncryptor(encryptor);
    when(encryptor.decrypt(new EncryptedValue(oldEncryptionKeyUuid, oldEncryptedPassword, oldNonce)))
      .thenReturn(USER_PASSWORD);
    when(encryptor.decrypt(new EncryptedValue(oldEncryptionKeyUuid, oldEncryptedGenerationParams, oldParametersNonce)))
      .thenReturn(userGenerationParametersString);

    when(encryptor.encrypt(eq(USER_PASSWORD)))
      .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE));
    when(encryptor.encrypt(eq(userGenerationParametersString)))
      .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE));

    subject.rotate();

    verify(encryptor, times(2)).decrypt(any());
    verify(encryptor).encrypt(USER_PASSWORD);
    verify(encryptor).encrypt(userGenerationParametersString);

    assertThat(userCredentialData.getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedValueData().getEncryptedValue(), equalTo(ENCRYPTED_PASSWORD));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), equalTo(ENCRYPTED_GENERATION_PARAMS));
    assertThat(userCredentialData.getNonce(), equalTo(NONCE));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getNonce(), equalTo(PARAMETERS_NONCE));
  }

  @Test
  public void setGenerationParameters_setsEncryptedGenerationParametersAndNonce() {
    when(encryptor.encrypt(eq(userGenerationParametersString)))
      .thenReturn(new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE));
    userCredentialData = new UserCredentialVersionData(CREDENTIAL_NAME);
    subject = new UserCredentialVersion(userCredentialData);
    subject.setEncryptor(encryptor);

    subject.setGenerationParameters(stringGenerationParameters);

    verify(encryptor, times(1)).encrypt(eq(userGenerationParametersString));

    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptionKeyUuid(), equalTo(ENCRYPTION_KEY_UUID));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), equalTo(ENCRYPTED_GENERATION_PARAMS));
    assertThat(userCredentialData.getEncryptedGenerationParameters().getNonce(), equalTo(PARAMETERS_NONCE));
  }

  @Test
  public void getGenerationParameters_decryptsGenerationParameters() {
    final EncryptedValue parameterEncryption = new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_GENERATION_PARAMS, PARAMETERS_NONCE);
    final EncryptedValue passwordEncryption = new EncryptedValue(ENCRYPTION_KEY_UUID, ENCRYPTED_PASSWORD, NONCE);
    when(encryptor.decrypt(parameterEncryption))
      .thenReturn(userGenerationParametersString);
    when(encryptor.decrypt(passwordEncryption))
      .thenReturn(USER_PASSWORD);

    userCredentialData = new UserCredentialVersionData();
    userCredentialData.setEncryptedValueData(passwordEncryption);
    userCredentialData.setEncryptedGenerationParameters(parameterEncryption);

    subject = new UserCredentialVersion(userCredentialData);
    subject.setEncryptor(encryptor);

    final StringGenerationParameters generationParameters = subject.getGenerationParameters();

    assertThat(generationParameters, samePropertyValuesAs(stringGenerationParameters));
    verify(encryptor, times(2)).decrypt(any());
  }

  @Test
  public void getGenerationParameters_returnsNullIfTheGenerationParametersAreNull() {
    userCredentialData = new UserCredentialVersionData();
    subject = new UserCredentialVersion(userCredentialData);
    subject.setEncryptor(encryptor);
    subject.setGenerationParameters(null);

    final StringGenerationParameters generationParameters = subject.getGenerationParameters();

    assertThat(generationParameters, equalTo(null));
  }
}
