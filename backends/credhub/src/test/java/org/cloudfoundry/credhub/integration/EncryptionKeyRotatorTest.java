package org.cloudfoundry.credhub.integration;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

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

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.cloudfoundry.credhub.CredhubTestApp;
import org.cloudfoundry.credhub.config.EncryptionKeyMetadata;
import org.cloudfoundry.credhub.config.EncryptionKeyProvider;
import org.cloudfoundry.credhub.config.EncryptionKeysConfiguration;
import org.cloudfoundry.credhub.data.EncryptionKeyCanaryDataService;
import org.cloudfoundry.credhub.domain.CertificateCredentialVersion;
import org.cloudfoundry.credhub.domain.CredentialVersion;
import org.cloudfoundry.credhub.domain.Encryptor;
import org.cloudfoundry.credhub.domain.PasswordCredentialVersion;
import org.cloudfoundry.credhub.entities.EncryptedValue;
import org.cloudfoundry.credhub.entities.EncryptionKeyCanary;
import org.cloudfoundry.credhub.entity.CertificateCredentialVersionData;
import org.cloudfoundry.credhub.entity.Credential;
import org.cloudfoundry.credhub.entity.CredentialVersionData;
import org.cloudfoundry.credhub.entity.PasswordCredentialVersionData;
import org.cloudfoundry.credhub.repositories.CredentialVersionRepository;
import org.cloudfoundry.credhub.requests.StringGenerationParameters;
import org.cloudfoundry.credhub.services.CredentialDataService;
import org.cloudfoundry.credhub.services.CredentialVersionDataService;
import org.cloudfoundry.credhub.services.EncryptionKey;
import org.cloudfoundry.credhub.services.EncryptionKeyRotator;
import org.cloudfoundry.credhub.services.EncryptionKeySet;
import org.cloudfoundry.credhub.services.InternalEncryptionService;
import org.cloudfoundry.credhub.services.PasswordBasedKeyProxy;
import org.cloudfoundry.credhub.services.PasswordEncryptionService;
import org.cloudfoundry.credhub.services.PasswordKeyProxyFactory;
import org.cloudfoundry.credhub.utils.CertificateStringConstants;
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cloudfoundry.credhub.helpers.JsonTestHelper.parse;
import static org.cloudfoundry.credhub.services.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static org.cloudfoundry.credhub.utils.AuthConstants.ALL_PERMISSIONS_TOKEN;
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
@SpringBootTest(classes = CredhubTestApp.class)
@RunWith(SpringRunner.class)
@Transactional
@SuppressFBWarnings(
  value = {
    "SS_SHOULD_BE_STATIC",
    "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE",
  },
  justification = "Test files generally don't need static fields."
)
public class EncryptionKeyRotatorTest {

  private final String passwordName = "/test-password";
  private final String name = "/" + this.getClass().getSimpleName();
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
  private InternalEncryptionService encryptionService;
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

  @Before
  public void beforeEach() throws Exception {
    mockMvc = MockMvcBuilders
      .webAppContextSetup(webApplicationContext)
      .apply(springSecurity())
      .build();

    encryptionService = new PasswordEncryptionService(passwordKeyProxyFactory);

    setActiveKey(0);
  }

  @Test
  public void whenDataExistsThatIsEncryptedWithUnknownKey_itShouldRotateDataThatItCanDecrypt()
    throws Exception {

    setupInitialContext();

    final List<CredentialVersionData> beforeRotation = credentialVersionRepository
      .findByEncryptedCredentialValueEncryptionKeyUuidIn(keySet.getInactiveUuids());
    final int numberToRotate = beforeRotation.size();

    assertThat(
      credentialVersionRepository.findOneByUuid(credentialWithUnknownKey.getUuid())
        .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));

    encryptionKeyRotator.rotate();

    final List<CredentialVersionData> afterRotation = credentialVersionRepository
      .findByEncryptedCredentialValueEncryptionKeyUuidIn(keySet.getInactiveUuids());
    final int numberToRotateWhenDone = afterRotation.size();

    assertThat(numberToRotate, equalTo(2));
    assertThat(numberToRotateWhenDone, equalTo(0));

    final List<UUID> uuids = beforeRotation.stream().map(CredentialVersionData::getUuid)
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

    final PasswordCredentialVersion rotatedPassword = (PasswordCredentialVersion) credentialVersionDataService
      .findMostRecent(passwordName);

    final StringGenerationParameters stringGenerationParameters = new StringGenerationParameters();
    stringGenerationParameters.setExcludeNumber(true);
    stringGenerationParameters.setLength(23);

    assertThat(rotatedPassword.getPassword(), equalTo("test-password-plaintext"));
    assertThat(rotatedPassword.getGenerationParameters(), samePropertyValuesAs(stringGenerationParameters));
  }

  @Test
  public void rotation_canRotatePasswordCredentials() throws Exception {
    final String passwordName = name + "-password";

    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
      .accept(APPLICATION_JSON)
      .contentType(APPLICATION_JSON)
      .content("{"
        + "  \"name\": \"" + passwordName + "\","
        + "  \"type\": \"password\""
        + "}");

    final String content = this.mockMvc.perform(post).andDo(print()).andExpect(status().isOk())
      .andReturn()
      .getResponse().getContentAsString();
    final String originalPassword = parse(content).get("value").textValue();

    final Credential credential = credentialDataService.find(passwordName);

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
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN);
    this.mockMvc.perform(get).andExpect(status().isOk())
      .andExpect(jsonPath(".data[0].value").value(originalPassword));
  }

  @Test
  public void rotation_canRotateCertificateCredentials() throws Exception {
    final String certificateName = name + "-certificate";

    final MockHttpServletRequestBuilder post = post("/api/v1/data")
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN)
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

    final String content = this.mockMvc.perform(post).andExpect(status().isOk()).andReturn()
      .getResponse().getContentAsString();
    final String originalCert = parse(content).get("value").get("private_key").textValue();

    final Credential credential = credentialDataService.find(certificateName);

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
      .header("Authorization", "Bearer " + ALL_PERMISSIONS_TOKEN);
    this.mockMvc.perform(get).andExpect(status().isOk())
      .andExpect(jsonPath("$.data[0].value.private_key").value(originalCert));
  }

  @Test
  public void rotation_removesOldCanaries() throws Exception {
    setupInitialContext();
    setActiveKey(1);
    encryptionKeyRotator.rotate();
    final List<UUID> oldCanaryUuids = keySet.getInactiveUuids();
    final List<EncryptionKeyCanary> allCanaries = encryptionKeyCanaryDataService.findAll();
    final List<UUID> remainingCanaryUuids = allCanaries.stream()
      .map(EncryptionKeyCanary::getUuid)
      .collect(Collectors.toList());

    assertThat(remainingCanaryUuids, hasItem(keySet.getActive().getUuid()));

    for (final UUID uuid : oldCanaryUuids) {
      assertThat(remainingCanaryUuids, not(hasItem(uuid)));
    }
  }

  private void setupInitialContext() throws Exception {
    createCredentialWithOriginalKey();
    createUnknownKey();
    createCredentialWithUnknownKey();
    final Key oldKey = createOldKey();
    createCertificateWithOldKey(oldKey);
    createPasswordWithOldKey(oldKey);
  }

  private void createPasswordWithOldKey(final Key oldKey) throws Exception {
    final EncryptedValue credentialEncryption = encryptionService
      .encrypt(oldCanary.getUuid(), oldKey, "test-password-plaintext");
    final PasswordCredentialVersionData passwordCredentialData = new PasswordCredentialVersionData(passwordName);
    passwordCredentialData.setEncryptedValueData(credentialEncryption);

    final StringGenerationParameters parameters = new StringGenerationParameters();
    parameters.setExcludeNumber(true);
    final EncryptedValue parameterEncryption = encryptionService
      .encrypt(oldCanary.getUuid(), oldKey,
        new ObjectMapper().writeValueAsString(parameters));
    passwordCredentialData.setEncryptedGenerationParameters(parameterEncryption);
    password = new PasswordCredentialVersion(passwordCredentialData);

    credentialVersionDataService.save(password);
  }

  private void createCredentialWithUnknownKey() {
    final CertificateCredentialVersionData certificateCredentialData2 = new CertificateCredentialVersionData("/unknown-key");

    credentialWithUnknownKey = new CertificateCredentialVersion(certificateCredentialData2);
    credentialWithUnknownKey.setEncryptor(encryptor);
    credentialWithUnknownKey.setPrivateKey("cert-private-key");

    certificateCredentialData2
      .getEncryptedValueData()
      .setEncryptionKeyUuid(unknownCanary.getUuid());
    credentialVersionDataService.save(credentialWithUnknownKey);
  }

  private void createUnknownKey() {
    unknownCanary = new EncryptionKeyCanary();
    unknownCanary.setEncryptedCanaryValue("bad-encrypted-value".getBytes(UTF_8));
    unknownCanary.setNonce("bad-nonce".getBytes(UTF_8));
    unknownCanary = encryptionKeyCanaryDataService.save(unknownCanary);
  }

  private void createCertificateWithOldKey(final Key oldKey) throws Exception {
    final EncryptedValue encryption = encryptionService
      .encrypt(oldCanary.getUuid(), oldKey, "old-certificate-private-key");
    final CertificateCredentialVersionData certificateCredentialData1 =
      new CertificateCredentialVersionData("/old-key");
    certificateCredentialData1.setEncryptedValueData(encryption);
    credentialVersionWithOldKey = new CertificateCredentialVersion(certificateCredentialData1);
    credentialVersionDataService.save(credentialVersionWithOldKey);
  }

  private Key createOldKey() throws Exception {
    final PasswordBasedKeyProxy keyProxy = new PasswordBasedKeyProxy("old-password", 1,
      encryptionService);
    final Key oldKey = keyProxy.deriveKey();

    oldCanary = new EncryptionKeyCanary();
    final EncryptedValue canaryEncryption = encryptionService.encrypt(null, oldKey, CANARY_VALUE);
    oldCanary.setEncryptedCanaryValue(canaryEncryption.getEncryptedValue());
    oldCanary.setNonce(canaryEncryption.getNonce());
    oldCanary = encryptionKeyCanaryDataService.save(oldCanary);

    keySet.add(new EncryptionKey(encryptionService, oldCanary.getUuid(), oldKey, "key-name"));

    return oldKey;
  }

  private void createCredentialWithOriginalKey() {
    credentialWithCurrentKey = new CertificateCredentialVersion("/current-key");
    credentialWithCurrentKey.setEncryptor(encryptor);
    credentialWithCurrentKey.setCa("my-ca");
    credentialWithCurrentKey.setCertificate(CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT);
    credentialWithCurrentKey.setPrivateKey("cert-private-key");

    credentialVersionDataService.save(credentialWithCurrentKey);
  }

  @SuppressFBWarnings(
    value = "RV_RETURN_VALUE_IGNORED_NO_SIDE_EFFECT",
    justification = "False positive - leave mockito settings alone"
  )
  private void setActiveKey(final int index) throws Exception {
    final List<EncryptionKeyMetadata> keys = new ArrayList<>();

    final List<EncryptionKeyProvider> providers = encryptionKeysConfiguration.getProviders();
    for (final EncryptionKeyProvider provider : providers) {
      for (final EncryptionKeyMetadata encryptionKeyMetadata : provider.getKeys()) {
        final EncryptionKeyMetadata clonedKey = new EncryptionKeyMetadata();

        clonedKey.setActive(false);
        clonedKey.setEncryptionPassword(encryptionKeyMetadata.getEncryptionPassword());

        keys.add(clonedKey);
      }
      keys.get(index).setActive(true);
      provider.setKeys(keys);
      provider.setProviderName("int");
    }

    doReturn(providers).when(encryptionKeysConfiguration).getProviders();
    keySet.reload();
  }
}


