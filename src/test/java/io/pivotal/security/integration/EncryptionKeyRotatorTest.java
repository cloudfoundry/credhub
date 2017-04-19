package io.pivotal.security.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.config.EncryptionKeyMetadata;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.entity.NamedCertificateSecretData;
import io.pivotal.security.entity.NamedPasswordSecretData;
import io.pivotal.security.entity.SecretName;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.EncryptionKeyRotator;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.service.PasswordBasedKeyProxy;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Slice;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.JsonHelper.parse;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static io.pivotal.security.service.PasswordBasedKeyProxy.generateSalt;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@RunWith(Spectrum.class)
public class EncryptionKeyRotatorTest {

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private SecretRepository secretRepository;

  @SpyBean
  private SecretDataService secretDataService;

  @SpyBean
  private EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private SecretNameRepository secretNameRepository;

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

  private NamedCertificateSecret secretWithCurrentKey;
  private NamedSecret secretWithOldKey;
  private NamedCertificateSecret secretWithUnknownKey;
  private NamedPasswordSecret password;
  private MockMvc mockMvc;
  private EncryptionKeyCanary unknownCanary;
  private EncryptionKeyCanary oldCanary;
  private String passwordName;

  {
    wireAndUnwire(this);

    describe("when data exists that is encrypted with an unknown key", () -> {
      beforeEach(() -> {
        secretWithCurrentKey = new NamedCertificateSecret("/current-key");
        secretWithCurrentKey
            .setEncryptor(encryptor)
            .setCa("my-ca")
            .setCertificate("my-cert")
            .setPrivateKey("cert-private-key");

        secretDataService.save(secretWithCurrentKey);

        final PasswordBasedKeyProxy keyProxy = new PasswordBasedKeyProxy("old-password",
            encryptionService);
        Key oldKey = keyProxy.deriveKey(generateSalt());

        oldCanary = new EncryptionKeyCanary();
        final Encryption canaryEncryption = encryptionService.encrypt(null, oldKey, CANARY_VALUE);
        oldCanary.setEncryptedCanaryValue(canaryEncryption.encryptedValue);
        oldCanary.setNonce(canaryEncryption.nonce);
        oldCanary = encryptionKeyCanaryDataService.save(oldCanary);

        when(encryptionKeyCanaryMapper.getKeyForUuid(oldCanary.getUuid())).thenReturn(oldKey);
        when(encryptionKeyCanaryMapper.getCanaryUuidsWithKnownAndInactiveKeys())
            .thenReturn(singletonList(oldCanary.getUuid()));

        final Encryption encryption = encryptionService
            .encrypt(oldCanary.getUuid(), oldKey, "old-certificate-private-key");
        NamedCertificateSecretData namedCertificateSecretData1 =
            new NamedCertificateSecretData("/old-key");
        namedCertificateSecretData1.setEncryptedValue(encryption.encryptedValue);
        namedCertificateSecretData1.setNonce(encryption.nonce);
        namedCertificateSecretData1.setEncryptionKeyUuid(oldCanary.getUuid());
        secretWithOldKey = new NamedCertificateSecret(namedCertificateSecretData1);
        secretDataService.save(secretWithOldKey);

        unknownCanary = new EncryptionKeyCanary();
        unknownCanary.setEncryptedCanaryValue("bad-encrypted-value".getBytes());
        unknownCanary.setNonce("bad-nonce".getBytes());
        unknownCanary = encryptionKeyCanaryDataService.save(unknownCanary);

        NamedCertificateSecretData namedCertificateSecretData2 = new NamedCertificateSecretData(
            "/unknown-key");
        secretWithUnknownKey = new NamedCertificateSecret(namedCertificateSecretData2);
        secretWithUnknownKey
            .setEncryptor(encryptor)
            .setPrivateKey("cert-private-key");
        namedCertificateSecretData2.setEncryptionKeyUuid(unknownCanary.getUuid());
        secretDataService.save(secretWithUnknownKey);

        passwordName = "/test-password";
        final Encryption secretEncryption = encryptionService
            .encrypt(oldCanary.getUuid(), oldKey, "test-password-plaintext");
        NamedPasswordSecretData namedPasswordSecretData = new NamedPasswordSecretData(passwordName);
        namedPasswordSecretData.setEncryptedValue(secretEncryption.encryptedValue);
        namedPasswordSecretData.setNonce(secretEncryption.nonce);
        namedPasswordSecretData.setNonce(secretEncryption.nonce);

        StringGenerationParameters parameters = new StringGenerationParameters();
        parameters.setExcludeNumber(true);
        final Encryption parameterEncryption = encryptionService
            .encrypt(oldCanary.getUuid(), oldKey,
                new ObjectMapper().writeValueAsString(parameters));
        namedPasswordSecretData.setEncryptedGenerationParameters(parameterEncryption.encryptedValue);
        namedPasswordSecretData.setParametersNonce(parameterEncryption.nonce);
        namedPasswordSecretData.setEncryptionKeyUuid(oldCanary.getUuid());

        password = new NamedPasswordSecret(namedPasswordSecretData);

        secretDataService.save(password);
      });

      it("should rotate data that it can decrypt (and it shouldn't loop forever!)", () -> {
        Slice<NamedSecret> beforeRotation = secretDataService
            .findEncryptedWithAvailableInactiveKey();
        int numberToRotate = beforeRotation.getNumberOfElements();

        assertThat(
            secretRepository.findOneByUuid(secretWithUnknownKey.getUuid())
                .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));

        encryptionKeyRotator.rotate();

        Slice<NamedSecret> afterRotation = secretDataService
            .findEncryptedWithAvailableInactiveKey();
        int numberToRotateWhenDone = afterRotation.getNumberOfElements();

        assertThat(numberToRotate, equalTo(2));
        assertThat(numberToRotateWhenDone, equalTo(0));

        List<UUID> uuids = beforeRotation.getContent().stream().map(secret -> secret.getUuid())
            .collect(Collectors.toList());

        // Gets updated to use current key:
        assertThat(
            secretRepository
                .findOneByUuid(secretWithOldKey.getUuid())
                .getEncryptionKeyUuid(),
            equalTo(encryptionKeyCanaryMapper.getActiveUuid())
        );

        assertThat(uuids, hasItem(secretWithOldKey.getUuid()));

        assertThat(secretRepository.findOneByUuid(password.getUuid())
                .getEncryptionKeyUuid(), equalTo(encryptionKeyCanaryMapper.getActiveUuid()));
        assertThat(uuids, hasItem(password.getUuid()));

        // Unchanged because we don't have the key:
        assertThat(
            secretRepository.findOneByUuid(secretWithUnknownKey.getUuid())
                .getEncryptionKeyUuid(), equalTo(unknownCanary.getUuid()));
        assertThat(uuids, not(hasItem(secretWithUnknownKey.getUuid())));

        // Unchanged because it's already up to date:
        assertThat(
            secretRepository.findOneByUuid(secretWithCurrentKey.getUuid())
                .getEncryptionKeyUuid(), equalTo(encryptionKeyCanaryMapper.getActiveUuid()));
        assertThat(uuids, not(hasItem(secretWithCurrentKey.getUuid())));

        NamedPasswordSecret rotatedPassword = (NamedPasswordSecret) secretDataService
            .findMostRecent(passwordName);
        assertThat(rotatedPassword.getPassword(), equalTo("test-password-plaintext"));
        assertThat(rotatedPassword.getGenerationParameters(), samePropertyValuesAs(
            new StringGenerationParameters()
                .setExcludeNumber(true)
                .setLength(23))
        );
      });
    });

    describe("rotation", () -> {
      beforeEach(() -> {
        mockMvc = MockMvcBuilders
            .webAppContextSetup(webApplicationContext)
            .apply(springSecurity())
            .build();
      });

      it("can rotate password secrets", () -> {
        MockHttpServletRequestBuilder post = post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"name\": \"/cred1\","
                + "  \"type\": \"password\""
                + "}");

        String content = this.mockMvc.perform(post).andExpect(status().isOk()).andReturn()
            .getResponse().getContentAsString();
        String originalPassword = parse(content).get("value").textValue();

        SecretName secretName = secretNameRepository
            .findOneByNameIgnoreCase("/cred1");

        final NamedPasswordSecretData firstEncryption =
            (NamedPasswordSecretData) secretRepository.findAllBySecretNameUuid(secretName.getUuid()).get(0);

        setActiveKey(1);

        encryptionKeyRotator.rotate();

        final NamedPasswordSecretData secondEncryption =
            (NamedPasswordSecretData) secretRepository.findAllBySecretNameUuid(secretName.getUuid()).get(0);
        assertThat(firstEncryption.getEncryptedValue(),
            not(equalTo(secondEncryption.getEncryptedValue())));
        assertThat(firstEncryption.getEncryptedGenerationParameters(),
            not(equalTo(secondEncryption.getEncryptedGenerationParameters())));

        final MockHttpServletRequestBuilder get = get("/api/v1/data?name=cred1")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
        this.mockMvc.perform(get).andExpect(status().isOk())
            .andExpect(jsonPath(".data[0].value").value(originalPassword));
      });

      it("can rotate certificate secrets", () -> {
        MockHttpServletRequestBuilder post = post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{"
                + "  \"name\": \"/cred1\","
                + "  \"type\": \"certificate\","
                + "  \"parameters\": { "
                + "    \"is_ca\": true,\n"
                + "    \"common_name\": \"Pivotal CA\""
                + "  }"
                + "}");

        String content = this.mockMvc.perform(post).andExpect(status().isOk()).andReturn()
            .getResponse().getContentAsString();
        String originalCert = parse(content).get("value").get("private_key").textValue();

        SecretName secretName = secretNameRepository
            .findOneByNameIgnoreCase("/cred1");

        final NamedCertificateSecretData firstEncryption =
            (NamedCertificateSecretData) secretRepository.findAllBySecretNameUuid(secretName.getUuid()).get(0);

        setActiveKey(1);

        encryptionKeyRotator.rotate();

        final NamedCertificateSecretData secondEncryption =
            (NamedCertificateSecretData) secretRepository.findAllBySecretNameUuid(secretName.getUuid()).get(0);
        assertThat(firstEncryption.getEncryptedValue(),
            not(equalTo(secondEncryption.getEncryptedValue())));

        final MockHttpServletRequestBuilder get = get("/api/v1/data?name=cred1")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN);
        this.mockMvc.perform(get).andExpect(status().isOk())
            .andExpect(jsonPath("$.data[0].value.private_key").value(originalCert));
      });
    });
  }

  private void setActiveKey(int index) {
    List<EncryptionKeyMetadata> keys = new ArrayList<>();
    for (EncryptionKeyMetadata encryptionKeyMetadata : encryptionKeysConfiguration.getKeys()) {
      keys.add(new EncryptionKeyMetadata(encryptionKeyMetadata.getDevKey(),
          encryptionKeyMetadata.getEncryptionKeyName(), false,
          encryptionKeyMetadata.getEncryptionPassword()));
    }

    keys.get(index).setActive(true);

    doReturn(
        keys
    ).when(encryptionKeysConfiguration).getKeys();

    encryptionKeyCanaryMapper.mapUuidsToKeys();
  }
}


