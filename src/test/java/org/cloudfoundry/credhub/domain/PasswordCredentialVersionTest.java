package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.JsonObjectMapper;
import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.UUID;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
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

  @Before
  public void beforeEach() throws Exception {
    canaryUuid = UUID.randomUUID();
    encryptor = mock(Encryptor.class);

    encryptedValue = "fake-encrypted-value".getBytes();
    nonce = "fake-nonce".getBytes();
    encryptedParametersValue = "fake-encrypted-parameters".getBytes();
    parametersNonce = "fake-parameters-nonce".getBytes();

    generationParameters = new StringGenerationParameters()
        .setExcludeLower(true)
        .setLength(10);

    String generationParametersJson = new JsonObjectMapper().writeValueAsString(generationParameters);

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
    subject.setPasswordAndGenerationParameters(PASSWORD, new StringGenerationParameters().setExcludeLower(true));

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

  @Test(expected = IllegalArgumentException.class)
  public void setPasswordAndGenerationParameters_throwsAnExceptionWhenSettingANullValue() {
    subject.setPasswordAndGenerationParameters(null, null);
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
    String expectedJsonString = "{\"exclude_lower\":true}";
    verify(encryptor, times(1)).encrypt(expectedJsonString);
  }
}
