package org.cloudfoundry.credhub.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.data.CredentialDataService;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.repository.CredentialVersionRepository;
import org.cloudfoundry.credhub.request.StringGenerationParameters;
import org.cloudfoundry.credhub.service.EncryptionKey;
import org.cloudfoundry.credhub.service.EncryptionKeyRotator;
import org.cloudfoundry.credhub.service.EncryptionKeySet;
import org.cloudfoundry.credhub.service.EncryptionService;
import org.cloudfoundry.credhub.service.InternalEncryptionService;
import org.cloudfoundry.credhub.service.PasswordBasedKeyProxy;
import org.cloudfoundry.credhub.service.PasswordKeyProxyFactory;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
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

import static org.cloudfoundry.credhub.helper.JsonTestHelper.parse;
import static org.cloudfoundry.credhub.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.cloudfoundry.credhub.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.samePropertyValuesAs;
import static org.hamcrest.core.IsNot.not;
import static org.mockito.Mockito.doReturn;
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

  @Autowired
  private CredentialDataService credentialDataService;

  @Autowired
  private EncryptionKeyRotator encryptionKeyRotator;

  @Autowired
  private EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @Autowired
  private PasswordKeyProxyFactory passwordKeyProxyFactory;

  private EncryptionService encryptionService;

  @SpyBean
  private EncryptionKeySet keySet;

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
  private final String passwordName = "/test-password";
  private final String name = "/" + this.getClass().getSimpleName();

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
        .webAppContextSetup(webApplicationContext)
        .apply(springSecurity())
        .build();

    encryptionService = new InternalEncryptionService(passwordKeyProxyFactory);

    setActiveKey(0);
  }

  @Test
  public void whenDataExistsThatIsEncryptedWithUnknownKey_itShouldRotateDataThatItCanDecrypt()
      throws Exception {

    setupInitialContext();

    List<CredentialVersionData> beforeRotation = credentialVersionRepository
        .findByEncryptedCredentialValueEncryptionKeyUuidIn(keySet.getInactiveUuids());
    int numberToRotate = beforeRotation.size();

    assertThat(
        credentialVersionRepository.findOneByUuid(credentialWithUnknownKey.getUuid())
            .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));

    encryptionKeyRotator.rotate();

    List<CredentialVersionData> afterRotation = credentialVersionRepository
        .findByEncryptedCredentialValueEncryptionKeyUuidIn(keySet.getInactiveUuids());
    int numberToRotateWhenDone = afterRotation.size();

    assertThat(numberToRotate, equalTo(2));
    assertThat(numberToRotateWhenDone, equalTo(0));

    List<UUID> uuids = beforeRotation.stream().map(CredentialVersionData::getUuid)
        .collect(Collectors.toList());

    // Gets updated to use current key:

    assertThat(
        credentialVersionRepository
            .findOneByUuid(credentialVersionWithOldKey.getUuid())
            .getEncryptionKeyUuid(),
        equalTo(keySet.getActive().getUuid())
    );

    assertThat(uuids, hasItem(credentialVersionWithOldKey.getUuid()));

    assertThat(credentialVersionRepository.findOneByUuid(password.getUuid())
        .getEncryptionKeyUuid(), equalTo(keySet.getActive().getUuid()));
    assertThat(uuids, hasItem(password.getUuid()));

    // Unchanged because we don't have the key:
    assertThat(
        credentialVersionRepository.findOneByUuid(credentialWithUnknownKey.getUuid())
            .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));
    assertThat(uuids, not(hasItem(credentialWithUnknownKey.getUuid())));

    // Unchanged because it's already up to date:
    assertThat(
        credentialVersionRepository.findOneByUuid(credentialWithCurrentKey.getUuid())
            .getEncryptionKeyUuid(), equalTo(keySet.getActive().getUuid()));
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

    final byte[] firstEncryptedValue = firstEncryption.getEncryptedValueData().getEncryptedValue();
    final byte[] firstEncryptedGenParams = firstEncryption.getEncryptedGenerationParameters().getEncryptedValue();

    setActiveKey(1);

    encryptionKeyRotator.rotate();

    final PasswordCredentialVersionData secondEncryption =
        (PasswordCredentialVersionData) credentialVersionRepository
            .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
            .get(0);
    assertThat(firstEncryptedValue,
        not(equalTo(secondEncryption.getEncryptedValueData().getEncryptedValue())));
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
            .getEncryptedValueData()
            .getEncryptedValue()
            .clone();

    setActiveKey(1);

    encryptionKeyRotator.rotate();

    final CertificateCredentialVersionData secondEncryption =
        (CertificateCredentialVersionData) credentialVersionRepository
            .findAllByCredentialUuidOrderByVersionCreatedAtDesc(credential.getUuid())
            .get(0);
    assertThat(firstEncryption, not(equalTo(secondEncryption.getEncryptedValueData().getEncryptedValue())));

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
    List<UUID> oldCanaryUuids = keySet.getInactiveUuids();
    List<EncryptionKeyCanary> allCanaries = encryptionKeyCanaryDataService.findAll();
    List<UUID> remainingCanaryUuids = allCanaries.stream()
        .map(EncryptionKeyCanary::getUuid)
        .collect(Collectors.toList());

    assertThat(remainingCanaryUuids, hasItem(keySet.getActive().getUuid()));

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
    final EncryptedValue credentialEncryption = encryptionService
        .encrypt(oldCanary.getUuid(), oldKey, "test-password-plaintext");
    PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    passwordCredentialData.setEncryptedValueData(credentialEncryption);

    StringGenerationParameters parameters = new StringGenerationParameters();
    parameters.setExcludeNumber(true);
    final EncryptedValue parameterEncryption = encryptionService
        .encrypt(oldCanary.getUuid(), oldKey,
            new ObjectMapper().writeValueAsString(parameters));
    passwordCredentialData.setEncryptedGenerationParameters(parameterEncryption);
    password = new PasswordCredentialVersion(passwordCredentialData);

    credentialVersionDataService.save(password);
  }

  private void createCredentialWithUnknownKey() {
    CertificateCredentialVersionData certificateCredentialData2 = new CertificateCredentialVersionData("/unknown-key");
    credentialWithUnknownKey = new CertificateCredentialVersion(certificateCredentialData2);
    credentialWithUnknownKey
        .setEncryptor(encryptor)
        .setPrivateKey("cert-private-key");
    certificateCredentialData2
        .getEncryptedValueData()
        .setEncryptionKeyUuid(unknownCanary.getUuid());
    credentialVersionDataService.save(credentialWithUnknownKey);
  }

  private void createUnknownKey() {
    unknownCanary = new EncryptionKeyCanary();
    unknownCanary.setEncryptedCanaryValue("bad-encrypted-value".getBytes());
    unknownCanary.setNonce("bad-nonce".getBytes());
    unknownCanary = encryptionKeyCanaryDataService.save(unknownCanary);
  }

  private void createCertificateWithOldKey(Key oldKey) throws Exception {
    final EncryptedValue encryption = encryptionService
        .encrypt(oldCanary.getUuid(), oldKey, "old-certificate-private-key");
    CertificateCredentialVersionData certificateCredentialData1 =
        new CertificateCredentialVersionData("/old-key");
    certificateCredentialData1.setEncryptedValueData(encryption);
    credentialVersionWithOldKey = new CertificateCredentialVersion(certificateCredentialData1);
    credentialVersionDataService.save(credentialVersionWithOldKey);
  }

  private Key createOldKey() throws Exception {
    final PasswordBasedKeyProxy keyProxy = new PasswordBasedKeyProxy("old-password", 1,
        encryptionService);
    Key oldKey = keyProxy.deriveKey();

    oldCanary = new EncryptionKeyCanary();
    final EncryptedValue canaryEncryption = encryptionService.encrypt(null, oldKey, CANARY_VALUE);
    oldCanary.setEncryptedCanaryValue(canaryEncryption.getEncryptedValue());
    oldCanary.setNonce(canaryEncryption.getNonce());
    oldCanary = encryptionKeyCanaryDataService.save(oldCanary);

    keySet.add(new EncryptionKey(encryptionService, oldCanary.getUuid(), oldKey));

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

  private void setActiveKey(int index) throws Exception {
    List<EncryptionKeyMetadata> keys = new ArrayList<>();

    for (EncryptionKeyMetadata encryptionKeyMetadata : encryptionKeysConfiguration.getKeys()) {
      EncryptionKeyMetadata clonedKey = new EncryptionKeyMetadata();

      clonedKey.setActive(false);
      clonedKey.setEncryptionPassword(encryptionKeyMetadata.getEncryptionPassword());
      clonedKey.setProviderType(encryptionKeyMetadata.getProviderType());

      keys.add(clonedKey);
    }

    keys.get(index).setActive(true);

    doReturn(keys).when(encryptionKeysConfiguration).getKeys();

    keySet.reload();
  }
}


