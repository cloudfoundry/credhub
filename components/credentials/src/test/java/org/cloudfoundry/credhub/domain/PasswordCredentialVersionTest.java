package org.cloudfoundry.credhub.domain;

import java.util.UUID;

import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.utils.JsonObjectMapper;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class PasswordCredentialVersionTest {

  private static final String PASSWORD = "my-password";

  private PasswordCredentialVersion subject;
  private PasswordCredentialVersionData passwordCredentialData;
  private Encryptor encryptor;
  private UUID canaryUuid;
  private StringGenerationParameters generationParameters;

  private byte[] encryptedValue;
  private byte[] nonce;
  private byte[] encryptedParametersValue;
  private byte[] parametersNonce;

  @BeforeEach
  public void beforeEach() throws Exception {
    canaryUuid = UUID.randomUUID();
    encryptor = mock(Encryptor.class);

    encryptedValue = "fake-encrypted-value".getBytes(UTF_8);
    nonce = "fake-nonce".getBytes(UTF_8);
    encryptedParametersValue = "fake-encrypted-parameters".getBytes(UTF_8);
    parametersNonce = "fake-parameters-nonce".getBytes(UTF_8);

    generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeLower(true);
    generationParameters.setLength(10);

    final String generationParametersJson = new JsonObjectMapper().writeValueAsString(generationParameters);

    when(encryptor.encrypt(null))
      .thenReturn(new EncryptedValue(canaryUuid, "", ""));
    final EncryptedValue encryption = new EncryptedValue(canaryUuid, encryptedValue, nonce);
    when(encryptor.encrypt(PASSWORD))
      .thenReturn(encryption);
    final EncryptedValue parametersEncryption = new EncryptedValue(canaryUuid, encryptedParametersValue, parametersNonce);
    when(encryptor.encrypt(eq(generationParametersJson)))
      .thenReturn(parametersEncryption);

    when(encryptor.decrypt(encryption))
      .thenReturn(PASSWORD);
    when(encryptor.decrypt(parametersEncryption))
      .thenReturn(generationParametersJson);

    passwordCredentialData = new PasswordCredentialVersionData("/Foo");
    subject = new PasswordCredentialVersion(passwordCredentialData);
    subject.setEncryptor(encryptor);
  }

  @Test
  public void getCredentialType_returnsPassword() {
    assertThat(subject.getCredentialType(), equalTo("password"));
  }

  @Test
  public void getGenerationParameters_shouldCallDecryptTwice() {
    final StringGenerationParameters stringGenerationParameters = new StringGenerationParameters();
    stringGenerationParameters.setExcludeLower(true);
    subject.setPasswordAndGenerationParameters(PASSWORD, stringGenerationParameters);

    subject.getGenerationParameters();

    verify(encryptor, times(2)).decrypt(any());
  }

  @Test
  public void getPassword_shouldCallDecryptOnce() {
    subject = new PasswordCredentialVersion("/Foo");
    subject.setEncryptor(encryptor);
    when(encryptor.encrypt(null))
      .thenReturn(new EncryptedValue(canaryUuid, "", ""));
    subject.setPasswordAndGenerationParameters(PASSWORD, null);

    subject.getPassword();

    verify(encryptor, times(1)).decrypt(any());
  }

  @Test
  public void setPasswordAndGenerationParameters_setsTheNonceAndEncryptedValue() {
    subject.setPasswordAndGenerationParameters(PASSWORD, null);
    assertThat(passwordCredentialData.getEncryptedValueData().getEncryptedValue(), notNullValue());
    assertThat(passwordCredentialData.getNonce(), notNullValue());
  }

  @Test
  public void setPasswordAndGenerationParameters_canDecryptValues() {
    subject.setPasswordAndGenerationParameters(PASSWORD, generationParameters);

    assertThat(subject.getPassword(), equalTo(PASSWORD));

    MatcherAssert.assertThat(subject.getGenerationParameters().getLength(), equalTo(11));
    MatcherAssert.assertThat(subject.getGenerationParameters().isExcludeLower(), equalTo(true));
    MatcherAssert.assertThat(subject.getGenerationParameters().isExcludeUpper(), equalTo(false));
  }

  @Test
  public void setPasswordAndGenerationParameters_throwsAnExceptionWhenSettingANullValue() {
    assertThrows(IllegalArgumentException.class, () ->
            subject.setPasswordAndGenerationParameters(null, null)
    );
  }

  @Test
  public void setPasswordAndGenerationParameters_setsParamsNonceAndEncryptedGenerationParameters() {
    subject.setPasswordAndGenerationParameters(PASSWORD, generationParameters);

    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getEncryptedValue(), notNullValue());
    assertThat(passwordCredentialData.getEncryptedGenerationParameters().getNonce(), notNullValue());
  }

  @Test
  public void setPasswordAndGenerationParameters_shouldSetNullsIfTheParamsAreNulls() {
    subject.setPasswordAndGenerationParameters(PASSWORD, null);
    assertThat(passwordCredentialData.getEncryptedGenerationParameters(), nullValue());
  }

  @Test
  public void setPasswordAndGenerationParameters_shouldSaveGenerationParams_AsSnakeCaseJson() {
    subject.setPasswordAndGenerationParameters(PASSWORD, generationParameters);
    final String expectedJsonString = "{\"exclude_lower\":true}";
    verify(encryptor, times(1)).encrypt(expectedJsonString);
  }
}
