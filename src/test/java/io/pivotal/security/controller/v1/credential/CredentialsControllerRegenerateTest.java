package io.pivotal.security.controller.v1.credential;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
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

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.credential.RsaKey;
import io.pivotal.security.credential.SshKey;
import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.entity.PasswordCredentialData;
import io.pivotal.security.generator.PassayStringCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
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

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CredentialsControllerRegenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  CredentialDataService credentialDataService;

  @MockBean
  PassayStringCredentialGenerator passwordGenerator;

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

  private AuditingHelper auditingHelper;

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

      auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
    });

    describe("regenerating a password", () -> {
      beforeEach(() -> {
        when(passwordGenerator.generateCredential(any(StringGenerationParameters.class)))
            .thenReturn(new StringCredential("generated-credential"));
        PasswordCredential originalCredential = new PasswordCredential("my-password");
        originalCredential.setEncryptor(encryptor);
        StringGenerationParameters generationParameters = new StringGenerationParameters();
        generationParameters.setExcludeNumber(true);
        originalCredential
            .setPasswordAndGenerationParameters("original-password", generationParameters);
        originalCredential.setVersionCreatedAt(frozenTime.plusSeconds(1));

        doReturn(originalCredential).when(credentialDataService).findMostRecent("my-password");

        doAnswer(invocation -> {
          PasswordCredential newCredential = invocation.getArgumentAt(0, PasswordCredential.class);
          uuid = UUID.randomUUID();
          newCredential.setUuid(uuid);
          newCredential.setVersionCreatedAt(frozenTime.plusSeconds(10));
          return newCredential;
        }).when(credentialDataService).save(any(PasswordCredential.class));

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

        ArgumentCaptor<PasswordCredential> argumentCaptor = ArgumentCaptor
            .forClass(PasswordCredential.class);
        verify(credentialDataService, times(1)).save(argumentCaptor.capture());

        PasswordCredential newPassword = argumentCaptor.getValue();

        assertThat(newPassword.getPassword(), equalTo("generated-credential"));
        assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
      });

      it("persists an audit entry", () -> {
        auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-password", "/api/v1/data", 200);
      });
    });

    describe("regenerating an rsa", () -> {
      beforeEach(() -> {
        when(rsaGenerator.generateCredential(any(RsaGenerationParameters.class)))
            .thenReturn(new RsaKey("public_key", "private_key"));
        RsaCredential originalCredential = new RsaCredential("my-rsa");
        originalCredential.setEncryptor(encryptor);
        originalCredential.setVersionCreatedAt(frozenTime.plusSeconds(1));

        doReturn(originalCredential).when(credentialDataService).findMostRecent("my-rsa");

        doAnswer(invocation -> {
          RsaCredential newCredential = invocation.getArgumentAt(0, RsaCredential.class);
          uuid = UUID.randomUUID();
          newCredential.setUuid(uuid);
          newCredential.setVersionCreatedAt(frozenTime.plusSeconds(10));
          return newCredential;
        }).when(credentialDataService).save(any(RsaCredential.class));

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

        ArgumentCaptor<RsaCredential> argumentCaptor = ArgumentCaptor
            .forClass(RsaCredential.class);
        verify(credentialDataService, times(1)).save(argumentCaptor.capture());

        RsaCredential newRsa = argumentCaptor.getValue();

        assertThat(newRsa.getPrivateKey(), equalTo("private_key"));
        assertThat(newRsa.getPublicKey(), equalTo("public_key"));
      });

      it("persists an audit entry", () -> {
        auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-rsa", "/api/v1/data", 200);
      });
    });

    describe("regenerating an ssh", () -> {
      beforeEach(() -> {
        when(sshGenerator.generateCredential(any(SshGenerationParameters.class)))
            .thenReturn(new SshKey("public_key", "private_key", null));
        SshCredential originalCredential = new SshCredential("my-ssh");
        originalCredential.setEncryptor(encryptor);
        originalCredential.setVersionCreatedAt(frozenTime.plusSeconds(1));

        doReturn(originalCredential).when(credentialDataService).findMostRecent("my-ssh");

        doAnswer(invocation -> {
          SshCredential newCredential = invocation.getArgumentAt(0, SshCredential.class);
          uuid = UUID.randomUUID();
          newCredential.setUuid(uuid);
          newCredential.setVersionCreatedAt(frozenTime.plusSeconds(10));
          return newCredential;
        }).when(credentialDataService).save(any(SshCredential.class));

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

        ArgumentCaptor<SshCredential> argumentCaptor = ArgumentCaptor
            .forClass(SshCredential.class);
        verify(credentialDataService, times(1)).save(argumentCaptor.capture());

        SshCredential newSsh = argumentCaptor.getValue();

        assertThat(newSsh.getPrivateKey(), equalTo("private_key"));
        assertThat(newSsh.getPublicKey(), equalTo("public_key"));
      });

      it("persists an audit entry", () -> {
        auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, "/my-ssh", "/api/v1/data", 200);
      });
    });

    describe("regenerate request for a non-existent credential", () -> {
      beforeEach(() -> {
        doReturn(null).when(credentialDataService).findMostRecent("my-password");

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
        auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, null, "/api/v1/data", 404);
      });
    });

    describe("when attempting to regenerate a non-generated password", () -> {
      beforeEach(() -> {
        PasswordCredential originalCredential = new PasswordCredential("my-password");
        originalCredential.setEncryptor(encryptor);
        originalCredential.setPasswordAndGenerationParameters("abcde", null);
        doReturn(originalCredential).when(credentialDataService).findMostRecent("my-password");

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
        auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, null, "/api/v1/data", 400);
      });
    });

    describe("when attempting to regenerate a password with parameters that can't be decrypted",
        () -> {
          beforeEach(() -> {
            PasswordCredentialData passwordCredentialData = new PasswordCredentialData(
                "my-password");
            PasswordCredential originalCredential = new PasswordCredential(passwordCredentialData);
            originalCredential.setEncryptor(encryptor);
            originalCredential
                .setPasswordAndGenerationParameters("abcde", new StringGenerationParameters());

            passwordCredentialData.setEncryptionKeyUuid(UUID.randomUUID());
            doReturn(originalCredential).when(credentialDataService).findMostRecent("my-password");

            response = mockMvc.perform(post("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
          });

          it("returns an error", () -> {
            // language=JSON
            String cannotRegenerate = "{\n" +
                "  \"error\": \"The credential could not be accessed with the provided encryption " +
                "keys. You must update your deployment configuration to continue.\"\n" +
                "}";

            response
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().json(cannotRegenerate));
          });
        });
  }
}
