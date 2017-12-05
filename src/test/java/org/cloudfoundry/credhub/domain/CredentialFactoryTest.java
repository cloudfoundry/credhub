package org.cloudfoundry.credhub.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.ImmutableMap;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.JsonObjectMapper;
import net.minidev.json.JSONObject;
import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.Arrays;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialFactoryTest {

  private static final String CREDENTIAL_NAME = "/test";
  private static final String PLAINTEXT_VALUE = "test-value";
  private final ImmutableMap<String, Object> jsonValueMap = ImmutableMap.<String, Object>builder()
      .put("key", "value")
      .put("array", Arrays.asList("foo", "bar"))
      .build();
  private final String jsonValueJsonString = JSONObject.toJSONString(jsonValueMap);
  private CredentialFactory subject;
  private JsonObjectMapper objectMapper;
  private StringGenerationParameters generationParameters;

  @Before
  public void setup() throws JsonProcessingException {
    Encryptor encryptor = mock(Encryptor.class);
    subject = new CredentialFactory(encryptor);
    objectMapper = new JsonObjectMapper();
    generationParameters = new StringGenerationParameters().setExcludeNumber(true).setLength(PLAINTEXT_VALUE.length());

    UUID encryptionKeyUuid = UUID.randomUUID();
    EncryptedValue encryption = new EncryptedValue(encryptionKeyUuid, PLAINTEXT_VALUE.getBytes(), "test-nonce".getBytes());
    when(encryptor.encrypt(PLAINTEXT_VALUE)).thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn(PLAINTEXT_VALUE);

    String generationParametersJsonString = objectMapper.writeValueAsString(generationParameters);
    EncryptedValue parametersEncryption = new EncryptedValue(encryptionKeyUuid, "test-parameters".getBytes(), "test-parameters-nonce".getBytes());
    when(encryptor.encrypt(generationParametersJsonString)).thenReturn(parametersEncryption);
    when(encryptor.decrypt(parametersEncryption)).thenReturn(generationParametersJsonString);

    EncryptedValue jsonEncryption =  new EncryptedValue(encryptionKeyUuid, jsonValueJsonString.getBytes(), "test-nonce".getBytes());
    when(encryptor.encrypt(jsonValueJsonString)).thenReturn(jsonEncryption);
    when(encryptor.decrypt(jsonEncryption)).thenReturn(jsonValueJsonString);
  }

  @Test
  public void makeCredentialFromRequest_givenAnExistingPassword_copiesCredentialNameReference() throws Exception {
    StringCredentialValue passwordValue = new StringCredentialValue(PLAINTEXT_VALUE);

    CredentialVersion existingCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
    CredentialVersion credentialVersion =
        subject.makeNewCredentialVersion(
            CredentialType.valueOf("password"),
            CREDENTIAL_NAME,
            passwordValue,
            existingCredentialVersion,
            generationParameters);
    assertThat(credentialVersion.getCredential(), equalTo(existingCredentialVersion.getCredential()));
  }

  @Test
  public void makeCredentialFromRequest_givenPasswordType_andNoExisting_returnsPasswordCredential() throws Exception {
    StringCredentialValue passwordValue = new StringCredentialValue(PLAINTEXT_VALUE);

    PasswordCredentialVersion credential =
        (PasswordCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("password"),
            CREDENTIAL_NAME,
            passwordValue,
            null,
            generationParameters);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getPassword(), equalTo(PLAINTEXT_VALUE));
    assertThat(credential.getGenerationParameters(), samePropertyValuesAs(generationParameters));
  }

  @Test
  public void makeCredentialFromRequest_givenValueType_andNoExisting_returnsValueCredential() throws Exception {
    StringCredentialValue passwordValue = new StringCredentialValue(PLAINTEXT_VALUE);

    ValueCredentialVersion credential =
        (ValueCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("value"),
            CREDENTIAL_NAME,
            passwordValue,
            null,
            null);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getValue(), equalTo(PLAINTEXT_VALUE));
  }

  @Test
  public void makeCredentialFromRequest_givenCertificateType_andNoExisting_returnsCertificateCredential() throws Exception {
    CertificateCredentialValue certificateValue = new CertificateCredentialValue(
        "ca-certificate",
        "certificate",
        PLAINTEXT_VALUE,
        "my-ca");

    CertificateCredentialVersion credential =
        (CertificateCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("certificate"),
            CREDENTIAL_NAME,
            certificateValue,
            null,
            null);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getCa(), equalTo("ca-certificate"));
    assertThat(credential.getCertificate(), equalTo("certificate"));
    assertThat(credential.getPrivateKey(), equalTo(PLAINTEXT_VALUE));
    assertThat(credential.getCaName(), equalTo("/my-ca"));
  }

  @Test
  public void makeCredentialFromRequest_givenRsaType_andNoExisting_returnsRsaCredential() throws Exception {
    RsaCredentialValue rsaValue = new RsaCredentialValue(
        "public-key",
        PLAINTEXT_VALUE);

    RsaCredentialVersion credential =
        (RsaCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("rsa"),
            CREDENTIAL_NAME,
            rsaValue,
            null,
            null);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getPublicKey(), equalTo("public-key"));
    assertThat(credential.getPrivateKey(), equalTo(PLAINTEXT_VALUE));
  }

  @Test
  public void makeCredentialFromRequest_givenSshType_andNoExisting_returnsSshCredential() throws Exception {
    SshCredentialValue sshValue = new SshCredentialValue(
        "public-key",
        PLAINTEXT_VALUE,
        null);

    SshCredentialVersion credential =
        (SshCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("ssh"),
            CREDENTIAL_NAME,
            sshValue,
            null,
            null);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getPublicKey(), equalTo("public-key"));
    assertThat(credential.getPrivateKey(), equalTo(PLAINTEXT_VALUE));
  }

  @Test
  public void makeCredentialFromRequest_givenJsonType_andNoExisting_returnsJsonCredential() throws Exception {
    JsonCredentialValue jsonValue = new JsonCredentialValue(jsonValueMap);

    JsonCredentialVersion credential =
        (JsonCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("json"),
            CREDENTIAL_NAME,
            jsonValue,
            null,
            null);
    assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getValue(), equalTo(jsonValueMap));
  }

  @Test
  public void makeCredentialFromRequest_givenUserType_andNoExisting_returnsUserCredential() throws Exception {
    UserCredentialValue userValue = new UserCredentialValue("username", PLAINTEXT_VALUE, "salt");

    UserCredentialVersion credential =
        (UserCredentialVersion) subject.makeNewCredentialVersion(
            CredentialType.valueOf("user"),
            CREDENTIAL_NAME,
            userValue,
            null,
            generationParameters);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getUsername(), equalTo("username"));
    assertThat(credential.getPassword(), equalTo(PLAINTEXT_VALUE));
    assertThat(credential.getSalt(), equalTo("salt"));
  }
}
