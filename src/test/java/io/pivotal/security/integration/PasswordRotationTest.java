package io.pivotal.security.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.PasswordGenerationParameters;
import io.pivotal.security.controller.v1.secret.SecretsController;
import io.pivotal.security.data.EncryptionKeyCanaryDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.EncryptionKeyCanary;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.service.Encryption;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.EncryptionService;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.service.EncryptionKeyCanaryMapper.CANARY_VALUE;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.security.Key;

import javax.crypto.spec.SecretKeySpec;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class PasswordRotationTest {
  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController secretsController;

  @Autowired
  SecretDataService secretDataService;

  @Autowired
  EncryptionKeyCanaryDataService encryptionKeyCanaryDataService;

  @SpyBean
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  EncryptionService encryptionService;

  private MockMvc mockMvc;
  private String passwordName;
  private EncryptionKeyCanary oldCanary;

  {
    wireAndUnwire(this, false);

    beforeEach(() -> {
      Key oldKey = new SecretKeySpec(parseHexBinary("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), 0, 16, "AES");
      oldCanary = new EncryptionKeyCanary();
      final Encryption canaryEncryption = encryptionService.encrypt(oldKey, CANARY_VALUE);
      oldCanary.setEncryptedValue(canaryEncryption.encryptedValue);
      oldCanary.setNonce(canaryEncryption.nonce);
      oldCanary = encryptionKeyCanaryDataService.save(oldCanary);

      when(encryptionKeyCanaryMapper.getKeyForUuid(oldCanary.getUuid())).thenReturn(oldKey);

      passwordName = "/test-password";
      NamedPasswordSecret password = new NamedPasswordSecret(passwordName);
      final Encryption secretEncryption = encryptionService.encrypt(oldKey, "test-password-plaintext");
      password.setEncryptedValue(secretEncryption.encryptedValue);
      password.setNonce(secretEncryption.nonce);
      PasswordGenerationParameters parameters = new PasswordGenerationParameters();
      parameters.setExcludeNumber(true);
      final Encryption parameterEncryption = encryptionService.encrypt(oldKey, new ObjectMapper().writeValueAsString(parameters));
      password.setEncryptedGenerationParameters(parameterEncryption.encryptedValue);
      password.setParametersNonce(parameterEncryption.nonce);
      password.setEncryptionKeyUuid(oldCanary.getUuid());

      secretDataService.save(password);

      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    });

    afterEach(() -> {
      secretDataService.deleteAll();
      encryptionKeyCanaryDataService.delete(oldCanary);
    });

    describe("when a password with parameters is rotated", () -> {
      it("should succeed", () -> {
        String requestBody = "{" +
            "\"type\":\"password\"," +
            "\"name\":\"" + passwordName + "\"," +
            "\"overwrite\":true" +
          "}";
        MockHttpServletRequestBuilder post = post("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content(requestBody);

        mockMvc.perform(post)
            .andExpect(status().is2xxSuccessful());
      });
    });
  }
}
