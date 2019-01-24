package org.cloudfoundry.credhub.domain;

import java.io.IOException;
import java.security.Security;
import java.util.UUID;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.credhub.constants.CredentialType;
import org.cloudfoundry.credhub.credential.CertificateCredentialValue;
import org.cloudfoundry.credhub.credential.JsonCredentialValue;
import org.cloudfoundry.credhub.credential.RsaCredentialValue;
import org.cloudfoundry.credhub.credential.SshCredentialValue;
import org.cloudfoundry.credhub.credential.StringCredentialValue;
import org.cloudfoundry.credhub.credential.UserCredentialValue;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.util.CertificateStringConstants;
import org.cloudfoundry.credhub.util.JsonObjectMapper;
import org.cloudfoundry.credhub.util.StringUtil;
import org.hamcrest.MatcherAssert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class CredentialFactoryTest {

  private static final String CREDENTIAL_NAME = "/test";
  private static final String PLAINTEXT_VALUE = "test-value";
  private static final String jsonValueJsonString = "{\"key\":\"value\",\"array\":[\"foo\",\"bar\"]}";
  private static final JsonNode jsonNode;

  static {
    JsonNode tmp = null;
    try {
      tmp = new JsonObjectMapper().readTree(jsonValueJsonString);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
    jsonNode = tmp;
  }

  private CredentialFactory subject;
  private JsonObjectMapper objectMapper;
  private StringGenerationParameters generationParameters;

  @Before
  public void setup() throws JsonProcessingException {

    if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleFipsProvider());
    }

    final Encryptor encryptor = mock(Encryptor.class);
    subject = new CredentialFactory(encryptor);
    objectMapper = new JsonObjectMapper();

    generationParameters = new StringGenerationParameters();
    generationParameters.setExcludeNumber(true);
    generationParameters.setLength(PLAINTEXT_VALUE.length());

    final UUID encryptionKeyUuid = UUID.randomUUID();
    final EncryptedValue encryption = new EncryptedValue(encryptionKeyUuid, PLAINTEXT_VALUE.getBytes(StringUtil.UTF_8), "test-nonce".getBytes(StringUtil.UTF_8));
    when(encryptor.encrypt(PLAINTEXT_VALUE)).thenReturn(encryption);
    when(encryptor.decrypt(encryption)).thenReturn(PLAINTEXT_VALUE);

    final String generationParametersJsonString = objectMapper.writeValueAsString(generationParameters);
    final EncryptedValue parametersEncryption = new EncryptedValue(encryptionKeyUuid, "test-parameters".getBytes(StringUtil.UTF_8), "test-parameters-nonce".getBytes(StringUtil.UTF_8));
    when(encryptor.encrypt(generationParametersJsonString)).thenReturn(parametersEncryption);
    when(encryptor.decrypt(parametersEncryption)).thenReturn(generationParametersJsonString);

    final EncryptedValue jsonEncryption = new EncryptedValue(encryptionKeyUuid, jsonValueJsonString.getBytes(StringUtil.UTF_8), "test-nonce".getBytes(StringUtil.UTF_8));
    when(encryptor.encrypt(jsonValueJsonString)).thenReturn(jsonEncryption);
    when(encryptor.decrypt(jsonEncryption)).thenReturn(jsonValueJsonString);
  }

  @Test
  public void makeCredentialFromRequest_givenAnExistingPassword_copiesCredentialNameReference() throws Exception {
    final StringCredentialValue passwordValue = new StringCredentialValue(PLAINTEXT_VALUE);

    final CredentialVersion existingCredentialVersion = new PasswordCredentialVersion(CREDENTIAL_NAME);
    final CredentialVersion credentialVersion =
      subject.makeNewCredentialVersion(
        CredentialType.valueOf("PASSWORD"),
        CREDENTIAL_NAME,
        passwordValue,
        existingCredentialVersion,
        generationParameters);
    assertThat(credentialVersion.getCredential(), equalTo(existingCredentialVersion.getCredential()));
  }

  @Test
  public void makeCredentialFromRequest_givenPasswordType_andNoExisting_returnsPasswordCredential() throws Exception {
    final StringCredentialValue passwordValue = new StringCredentialValue(PLAINTEXT_VALUE);

    final PasswordCredentialVersion credential =
      (PasswordCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("PASSWORD"),
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
    final StringCredentialValue passwordValue = new StringCredentialValue(PLAINTEXT_VALUE);

    final ValueCredentialVersion credential =
      (ValueCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("VALUE"),
        CREDENTIAL_NAME,
        passwordValue,
        null,
        null);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getValue(), equalTo(PLAINTEXT_VALUE));
  }

  @Test
  public void makeCredentialFromRequest_givenCertificateType_andNoExisting_returnsCertificateCredential() throws Exception {
    final CertificateCredentialValue certificateValue = new CertificateCredentialValue(
      CertificateStringConstants.SELF_SIGNED_CA_CERT,
      CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT,
      PLAINTEXT_VALUE,
      "my-ca"
    );

    final CertificateCredentialVersion credential =
      (CertificateCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("CERTIFICATE"),
        CREDENTIAL_NAME,
        certificateValue,
        null,
        null);
    MatcherAssert.assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getCa(), equalTo(CertificateStringConstants.SELF_SIGNED_CA_CERT));
    assertThat(credential.getCertificate(), equalTo(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT));
    assertThat(credential.getPrivateKey(), equalTo(PLAINTEXT_VALUE));
    assertThat(credential.getCaName(), equalTo("/my-ca"));
  }

  @Test
  public void makeCredentialFromRequest_givenRsaType_andNoExisting_returnsRsaCredential() throws Exception {
    final RsaCredentialValue rsaValue = new RsaCredentialValue(
      "public-key",
      PLAINTEXT_VALUE);

    final RsaCredentialVersion credential =
      (RsaCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("RSA"),
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
    final SshCredentialValue sshValue = new SshCredentialValue(
      "public-key",
      PLAINTEXT_VALUE,
      null);

    final SshCredentialVersion credential =
      (SshCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("SSH"),
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
    final JsonCredentialValue jsonValue = new JsonCredentialValue(jsonNode);

    final JsonCredentialVersion credential =
      (JsonCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("JSON"),
        CREDENTIAL_NAME,
        jsonValue,
        null,
        null);
    assertThat(credential.getCredential().getName(), equalTo(CREDENTIAL_NAME));
    assertThat(credential.getValue(), equalTo(jsonNode));
  }

  @Test
  public void makeCredentialFromRequest_givenUserType_andNoExisting_returnsUserCredential() throws Exception {
    final UserCredentialValue userValue = new UserCredentialValue("username", PLAINTEXT_VALUE, "salt");

    final UserCredentialVersion credential =
      (UserCredentialVersion) subject.makeNewCredentialVersion(
        CredentialType.valueOf("USER"),
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
