package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.AuditingHelper.verifyAuditing;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerRegenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  SecretDataService secretDataService;

  @MockBean
  PassayStringSecretGenerator passwordGenerator;

  @MockBean
  SshGenerator sshGenerator;

  @MockBean
  RsaGenerator rsaGenerator;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private Consumer<Long> fakeTimeSetter;

  private ResultActions response;

  private UUID uuid;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("regenerating a password", () -> {
      beforeEach(() -> {
        when(passwordGenerator.generateSecret(any(PasswordGenerationParameters.class)))
            .thenReturn(new Password("generated-secret"));
        NamedPasswordSecret originalSecret = new NamedPasswordSecret("my-password");
        originalSecret.setEncryptor(encryptor);
        originalSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
        PasswordGenerationParameters generationParameters = new PasswordGenerationParameters();
        generationParameters.setExcludeNumber(true);
        originalSecret
            .setPasswordAndGenerationParameters("original-password", generationParameters);
        originalSecret.setVersionCreatedAt(frozenTime.plusSeconds(1));

        doReturn(originalSecret).when(secretDataService).findMostRecent("my-password");

        doAnswer(invocation -> {
          NamedPasswordSecret newSecret = invocation.getArgumentAt(0, NamedPasswordSecret.class);
          uuid = UUID.randomUUID();
          newSecret.setUuid(uuid);
          newSecret.setVersionCreatedAt(frozenTime.plusSeconds(10));
          return newSecret;
        }).when(secretDataService).save(any(NamedPasswordSecret.class));

        fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

        response = mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
      });

      it("should regenerate the password", () -> {
        response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("password"))
            .andExpect(jsonPath("$.id").value(uuid.toString()))
            .andExpect(
                jsonPath("$.version_created_at").value(frozenTime.plusSeconds(10).toString()));

        ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor
            .forClass(NamedPasswordSecret.class);
        verify(secretDataService, times(1)).save(argumentCaptor.capture());

        NamedPasswordSecret newPassword = argumentCaptor.getValue();

        assertThat(newPassword.getPassword(), equalTo("generated-secret"));
        assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
      });

      it("persists an audit entry", () -> {
        verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, "/my-password", 200);
      });
    });

    describe("regenerating an rsa", () -> {
      beforeEach(() -> {
        when(rsaGenerator.generateSecret(any(RsaGenerationParameters.class)))
            .thenReturn(new RsaKey("public_key", "private_key"));
        NamedRsaSecret originalSecret = new NamedRsaSecret("my-rsa");
        originalSecret.setEncryptor(encryptor);
        originalSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
        originalSecret.setVersionCreatedAt(frozenTime.plusSeconds(1));

        doReturn(originalSecret).when(secretDataService).findMostRecent("my-rsa");

        doAnswer(invocation -> {
          NamedRsaSecret newSecret = invocation.getArgumentAt(0, NamedRsaSecret.class);
          uuid = UUID.randomUUID();
          newSecret.setUuid(uuid);
          newSecret.setVersionCreatedAt(frozenTime.plusSeconds(10));
          return newSecret;
        }).when(secretDataService).save(any(NamedRsaSecret.class));

        fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

        response = mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-rsa\"}"));
      });

      it("should regenerate the rsa", () -> {
        response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("rsa"))
            .andExpect(jsonPath("$.id").value(uuid.toString()))
            .andExpect(
                jsonPath("$.version_created_at").value(frozenTime.plusSeconds(10).toString()));

        ArgumentCaptor<NamedRsaSecret> argumentCaptor = ArgumentCaptor
            .forClass(NamedRsaSecret.class);
        verify(secretDataService, times(1)).save(argumentCaptor.capture());

        NamedRsaSecret newRsa = argumentCaptor.getValue();

        assertThat(newRsa.getPrivateKey(), equalTo("private_key"));
        assertThat(newRsa.getPublicKey(), equalTo("public_key"));
      });

      it("persists an audit entry", () -> {
        verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, "/my-rsa", 200);
      });
    });

    describe("regenerating an ssh", () -> {
      beforeEach(() -> {
        when(sshGenerator.generateSecret(any(SshGenerationParameters.class)))
            .thenReturn(new SshKey("public_key", "private_key", null));
        NamedSshSecret originalSecret = new NamedSshSecret("my-ssh");
        originalSecret.setEncryptor(encryptor);
        originalSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
        originalSecret.setVersionCreatedAt(frozenTime.plusSeconds(1));

        doReturn(originalSecret).when(secretDataService).findMostRecent("my-ssh");

        doAnswer(invocation -> {
          NamedSshSecret newSecret = invocation.getArgumentAt(0, NamedSshSecret.class);
          uuid = UUID.randomUUID();
          newSecret.setUuid(uuid);
          newSecret.setVersionCreatedAt(frozenTime.plusSeconds(10));
          return newSecret;
        }).when(secretDataService).save(any(NamedSshSecret.class));

        fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

        response = mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-ssh\"}"));
      });

      it("should regenerate the ssh", () -> {
        response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("ssh"))
            .andExpect(jsonPath("$.id").value(uuid.toString()))
            .andExpect(
                jsonPath("$.version_created_at").value(frozenTime.plusSeconds(10).toString()));

        ArgumentCaptor<NamedSshSecret> argumentCaptor = ArgumentCaptor
            .forClass(NamedSshSecret.class);
        verify(secretDataService, times(1)).save(argumentCaptor.capture());

        NamedSshSecret newSsh = argumentCaptor.getValue();

        assertThat(newSsh.getPrivateKey(), equalTo("private_key"));
        assertThat(newSsh.getPublicKey(), equalTo("public_key"));
      });

      it("persists an audit entry", () -> {
        verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, "/my-ssh", 200);
      });
    });

    describe("regenerate request for a non-existent secret", () -> {
      beforeEach(() -> {
        doReturn(null).when(secretDataService).findMostRecent("my-password");

        response = mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
      });

      it("returns an error", () -> {
        String notFoundJson = "{" +
            "  \"error\": \"Credential not found. " +
            "Please validate your input and retry your request.\"" +
            "}";

        response
            .andExpect(status().isNotFound())
            .andExpect(content().json(notFoundJson));
      });

      it("persists an audit entry", () -> {
        // https://www.pivotaltracker.com/story/show/139762105
        verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, null, 404);
      });
    });

    describe("when attempting to regenerate a non-generated password", () -> {
      beforeEach(() -> {
        NamedPasswordSecret originalSecret = new NamedPasswordSecret("my-password");
        originalSecret.setEncryptor(encryptor);
        originalSecret.setPasswordAndGenerationParameters("abcde", null);
        doReturn(originalSecret).when(secretDataService).findMostRecent("my-password");

        response = mockMvc.perform(post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
      });

      it("returns an error", () -> {
        String cannotRegenerateJson = "{" +
            "  \"error\": \"The password could not be regenerated because the value was " +
            "statically set. Only generated passwords may be regenerated.\"" +
            "}";

        response.andExpect(content().json(cannotRegenerateJson));
      });

      it("persists an audit entry", () -> {
        // https://www.pivotaltracker.com/story/show/139762105
        verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, null, 400);
      });
    });

    describe("when attempting to regenerate a password with parameters that can't be decrypted",
        () -> {
          beforeEach(() -> {
            NamedPasswordSecret originalSecret = new NamedPasswordSecret("my-password");
            originalSecret.setEncryptor(encryptor);
            originalSecret
                .setPasswordAndGenerationParameters("abcde", new PasswordGenerationParameters());
            originalSecret.setEncryptionKeyUuid(UUID.randomUUID());

            doReturn(originalSecret).when(secretDataService).findMostRecent("my-password");

            response = mockMvc.perform(post("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
          });

          it("returns an error", () -> {
            // language=JSON
            String cannotRegenerateJson = "{\n" +
                "  \"error\": \"The credential could not be accessed with the provided encryption "
                +
                "keys. You must update your deployment configuration to continue.\"\n" +
                "}";

            response
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().json(cannotRegenerateJson));
          });
        });
  }
}
