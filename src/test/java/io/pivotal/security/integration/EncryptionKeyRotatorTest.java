package io.pivotal.security.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.data.CredentialVersionDataService;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.domain.CertificateCredentialVersion;
import io.pivotal.security.domain.CredentialVersion;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredentialVersion;
import io.pivotal.security.entity.CertificateCredentialVersionData;
import io.pivotal.security.entity.Credential;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.entity.PasswordCredentialVersionData;
import io.pivotal.security.repository.CredentialVersionRepository;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.EncryptionKeyRotator;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.PasswordBasedKeyProxy;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Slice;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static io.pivotal.security.helper.JsonTestHelper.parse;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static java.util.Collections.singletonList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsNot.not;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@RunWith(SpringRunner.class)
@Transactional
public class EncryptionKeyRotatorTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private CredentialVersionRepository credentialVersionRepository;

  @SpyBean
  private CredentialVersionDataService credentialVersionDataService;

  @SpyBean
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private CredentialDataService credentialDataService;

  @Autowired
  private EncryptionKeyRotator encryptionKeyRotator;

  @Autowired
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  private EncryptionService encryptionService;

  @Autowired
  private Encryptor encryptor;

  @SpyBean
  private EncryptionKeysConfiguration encryptionKeysConfiguration;

  private CertificateCredentialVersion credentialWithCurrentKey;
  private CredentialVersion credentialVersionWithOldKey;
  private CertificateCredentialVersion credentialWithUnknownKey;
  private PasswordCredentialVersion password;
  private MockMvc mockMvc;
  private EncryptionKeyCanary unknownCanary;
  private EncryptionKeyCanary oldCanary;
  private String passwordName;
  private final String name = "/" + this.getClass().getSimpleName();

  @Before
  public void beforeEach() {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    setActiveKey(0);
  }

  @Test
  public void whenDataExistsThatIsEncryptedWithUnknownKey_itShouldRotateDataThatItCanDecrypt()
      throws Exception {

    setupInitialContext();

    Slice<CredentialVersion> beforeRotation = credentialVersionDataService
        .findEncryptedWithAvailableInactiveKey();
    int numberToRotate = beforeRotation.getNumberOfElements();

    assertThat(
        credentialVersionRepository.findOneByUuid(credentialWithUnknownKey.getUuid())
            .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));

    encryptionKeyRotator.rotate();

    Slice<CredentialVersion> afterRotation = credentialVersionDataService
        .findEncryptedWithAvailableInactiveKey();
    int numberToRotateWhenDone = afterRotation.getNumberOfElements();

    assertThat(numberToRotate, equalTo(2));
    assertThat(numberToRotateWhenDone, equalTo(0));

    List<UUID> uuids = beforeRotation.getContent().stream().map(CredentialVersion::getUuid)
        .collect(Collectors.toList());

    // Gets updated to use current key:
    assertThat(
        credentialVersionRepository
            .findOneByUuid(credentialVersionWithOldKey.getUuid())
            .getEncryptionKeyUuid(),
        equalTo(encryptionKeyCanaryMapper.getActiveUuid())
    );

    assertThat(uuids, hasItem(credentialVersionWithOldKey.getUuid()));

    assertThat(credentialVersionRepository.findOneByUuid(password.getUuid())
        .getEncryptionKeyUuid(), equalTo(encryptionKeyCanaryMapper.getActiveUuid()));
    assertThat(uuids, hasItem(password.getUuid()));

    // Unchanged because we don't have the key:
    assertThat(
        credentialVersionRepository.findOneByUuid(credentialWithUnknownKey.getUuid())
            .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));
    assertThat(uuids, not(hasItem(credentialWithUnknownKey.getUuid())));

    // Unchanged because it's already up to date:
    assertThat(
        credentialVersionRepository.findOneByUuid(credentialWithCurrentKey.getUuid())
            .getEncryptionKeyUuid(), equalTo(encryptionKeyCanaryMapper.getActiveUuid()));
    assertThat(uuids, not(hasItem(credentialWithCurrentKey.getUuid())));

    PasswordCredentialVersion rotatedPassword = (PasswordCredentialVersion) credentialVersionDataService
        .findMostRecent(passwordName);
    assertThat(rotatedPassword.getPassword(), equalTo("test-password-plaintext"));
    assertThat(rotatedPassword.getGenerationParameters(), samePropertyValuesAs(
        new StringGenerationParameters()
            .setExcludeNumber(true)
            .setLength(23)));
  }

  @Test
  public void rotation_canRotatePasswordCredentials() throws Exception {
    String passwordName = name + "-password";

    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + passwordName + "\","
            + "  \"type\": \"password\""
            + "}");

    String content = this.mockMvc.perform(post).andDo(print()).andExpect(status().isOk())
        .andReturn()
        .getResponse().getContentAsString();
    String originalPassword = parse(content).get("value").textValue();

    Credential credential = credentialDataService.find(passwordName);

    final PasswordCredentialVersionData firstEncryption =
        (PasswordCredentialVersionData) credentialVersionRepository
            .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
            .get(0);

    final byte[] firstEncryptedValue = firstEncryption.getEncryptedValue().clone();
    final byte[] firstEncryptedGenParams = firstEncryption.getEncryptedGenerationParameters().getEncryptedValue().clone();

    setActiveKey(1);

    encryptionKeyRotator.rotate();

    final PasswordCredentialVersionData secondEncryption =
        (PasswordCredentialVersionData) credentialVersionRepository
            .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
            .get(0);
    assertThat(firstEncryptedValue,
        not(equalTo(secondEncryption.getEncryptedValue())));
    assertThat(firstEncryptedGenParams,
        not(equalTo(secondEncryption.getEncryptedGenerationParameters())));

    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + passwordName)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    this.mockMvc.perform(get).andExpect(status().isOk())
        .andExpect(jsonPath(".data[0].value").value(originalPassword));
  }

  @Test
  public void rotation_canRotateCertificateCredentials() throws Exception {
    String certificateName = name + "-certificate";

    MockHttpServletRequestBuilder post = post("/api/v1/data")
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{"
            + "  \"name\": \"" + certificateName + "\","
            + "  \"type\": \"certificate\","
            + "  \"parameters\": { "
            + "    \"is_ca\": true,\n"
            + "    \"common_name\": \"Pivotal CA\""
            + "  }"
            + "}");

    String content = this.mockMvc.perform(post).andExpect(status().isOk()).andReturn()
        .getResponse().getContentAsString();
    String originalCert = parse(content).get("value").get("private_key").textValue();

    Credential credential = credentialDataService.find(certificateName);

    final byte[] firstEncryption =
        credentialVersionRepository
            .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid()).get(0)
            .getEncryptedValue()
            .clone();

    setActiveKey(1);

    encryptionKeyRotator.rotate();

    final CertificateCredentialVersionData secondEncryption =
        (CertificateCredentialVersionData) credentialVersionRepository
            .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
            .get(0);
    assertThat(firstEncryption, not(equalTo(secondEncryption.getEncryptedValue())));

    final MockHttpServletRequestBuilder get = get("/api/v1/data?name=" + certificateName)
        .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
    this.mockMvc.perform(get).andExpect(status().isOk())
        .andExpect(jsonPath("$.data[0].value.private_key").value(originalCert));
  }

  @Test
  public void rotation_removesOldCanaries() throws Exception {
    setupInitialContext();
    setActiveKey(1);
    encryptionKeyRotator.rotate();
    List<UUID> oldCanaryUuids = encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys();
    List<EncryptionKeyCanary> allCanaries = encryptionKeyCanaryDataService.findAll();
    List<UUID> remainingCanaryUuids = allCanaries.stream()
        .map(EncryptionKeyCanary::getUuid)
        .collect(Collectors.toList());

    assertThat(remainingCanaryUuids, hasItem(encryptionKeyCanaryMapper.getActiveUuid()));

    for (UUID uuid : oldCanaryUuids) {
      assertThat(remainingCanaryUuids, not(hasItem(uuid)));
    }
  }

  private void setupInitialContext() throws Exception {
    createCredentialWithOriginalKey();
    createUnknownKey();
    createCredentialWithUnknownKey();
    Key oldKey = createOldKey();
    createCertificateWithOldKey(oldKey);
    createPasswordWithOldKey(oldKey);
  }

  private void createPasswordWithOldKey(Key oldKey) throws Exception {
    passwordName = "/test-password";
    final Encryption credentialEncryption = encryptionService
        .encrypt(oldCanary.getUuid(), oldKey, "test-password-plaintext");
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    passwordCredentialData.setValuesFromEncryption(credentialEncryption);

    StringGenerationParameters parameters = new StringGenerationParameters();
    parameters.setExcludeNumber(true);
    final Encryption parameterEncryption = encryptionService
        .encrypt(oldCanary.getUuid(), oldKey,
            new ObjectMapper().writeValueAsString(parameters));
    passwordCredentialData.setEncryptedGenerationParameters(parameterEncryption);
    password = new PasswordCredentialVersion(passwordCredentialData);

    credentialVersionDataService.save(password);
  }

  private void createCredentialWithUnknownKey() {
    CertificateCredentialVersionData certificateCredentialData2 = new CertificateCredentialVersionData(
        "/unknown-key");
    credentialWithUnknownKey = new CertificateCredentialVersion(certificateCredentialData2);
    credentialWithUnknownKey
        .setEncryptor(encryptor)
        .setPrivateKey("cert-private-key");
    certificateCredentialData2.setEncryptionKeyUuid(unknownCanary.getUuid());
    credentialVersionDataService.save(credentialWithUnknownKey);
  }

  private void createUnknownKey() {
    unknownCanary = new EncryptionKeyCanary();
    unknownCanary.setEncryptedCanaryValue("bad-encrypted-value".getBytes());
    unknownCanary.setNonce("bad-nonce".getBytes());
    unknownCanary = encryptionKeyCanaryDataService.save(unknownCanary);
  }

  private void createCertificateWithOldKey(Key oldKey) throws Exception {
    final Encryption encryption = encryptionService
        .encrypt(oldCanary.getUuid(), oldKey, "old-certificate-private-key");
    CertificateCredentialVersionData certificateCredentialData1 =
        new CertificateCredentialVersionData("/old-key");
    certificateCredentialData1.setValuesFromEncryption(encryption);
    credentialVersionWithOldKey = new CertificateCredentialVersion(certificateCredentialData1);
    credentialVersionDataService.save(credentialVersionWithOldKey);
  }

  private Key createOldKey() throws Exception {
    final PasswordBasedKeyProxy keyProxy = new PasswordBasedKeyProxy("old-password", 1,
        encryptionService);
    Key oldKey = keyProxy.deriveKey();

    oldCanary = new EncryptionKeyCanary();
    final Encryption canaryEncryption = encryptionService.encrypt(null, oldKey, CANARY_VALUE);
    oldCanary.setEncryptedCanaryValue(canaryEncryption.encryptedValue);
    oldCanary.setNonce(canaryEncryption.nonce);
    oldCanary = encryptionKeyCanaryDataService.save(oldCanary);

    when(encryptionKeyCanaryMapper.getKeyForUuid(oldCanary.getUuid())).thenReturn(oldKey);
    when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
        .thenReturn(singletonList(oldCanary.getUuid()));
    return oldKey;
  }

  private void createCredentialWithOriginalKey() {
    credentialWithCurrentKey = new CertificateCredentialVersion("/current-key");
    credentialWithCurrentKey
        .setEncryptor(encryptor)
        .setCa("my-ca")
        .setCertificate("my-cert")
        .setPrivateKey("cert-private-key");

    credentialVersionDataService.save(credentialWithCurrentKey);
  }

  private void setActiveKey(int index) {
    List<EncryptionKeyMetadata> keys = new ArrayList<>();

    for (EncryptionKeyMetadata encryptionKeyMetadata : encryptionKeysConfiguration.getKeys()) {
      EncryptionKeyMetadata clonedKey = new EncryptionKeyMetadata();

      clonedKey.setActive(false);
      clonedKey.setEncryptionPassword(encryptionKeyMetadata.getEncryptionPassword());

      keys.add(clonedKey);
    }

    keys.get(index).setActive(true);

    doReturn(keys).when(encryptionKeysConfiguration).getKeys();

    encryptionKeyCanaryMapper.mapUuidsToKeys();
  }
}


