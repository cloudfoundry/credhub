package io.pivotal.security.controller.v1.secret;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.fake.FakeAuditLogService;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerRegenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  FakeAuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  @MockBean
  PassayStringSecretGenerator passwordGenerator;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;
  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;
  @Autowired
  private Encryptor encryptor;
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
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
      when(passwordGenerator.generateSecret(any(PasswordGenerationParameters.class)))
          .thenReturn(new Password("generated-secret"));
    });

    describe("regenerating a password", () -> {
      beforeEach(() -> {
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

        resetAuditLogMock();

        fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

        response = mockMvc.perform(post("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
      });

      it("should regenerate the secret", () -> {
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
        ArgumentCaptor<Supplier> supplierArgumentCaptor = ArgumentCaptor.forClass(Supplier.class);
        ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor
            .forClass(AuditRecordBuilder.class);
        verify(auditLogService, times(1)).performWithAuditing(auditRecordParamsCaptor.capture(),
            supplierArgumentCaptor.capture());

        Supplier<ResponseEntity<?>> action = supplierArgumentCaptor.getValue();
        assertThat(action.get().getStatusCode(), equalTo(HttpStatus.OK));

        assertThat(auditRecordParamsCaptor.getValue().getOperationCode(),
            equalTo(CREDENTIAL_UPDATE));
      });
    });

    describe("regenerate request for a non-existent secret", () -> {
      beforeEach(() -> {
        doReturn(null).when(secretDataService).findMostRecent("my-password");

        response = mockMvc.perform(post("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
      });

      it("returns an error", () -> {
        String notFoundJson = "{\"error\": \"Credential not found. "
            + "Please validate your input and retry your request.\"}";

        response.andExpect(content().json(notFoundJson));
      });

      it("persists an audit entry", () -> {
        ArgumentCaptor<Supplier> supplierArgumentCaptor = ArgumentCaptor.forClass(Supplier.class);
        ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor
            .forClass(AuditRecordBuilder.class);
        verify(auditLogService, times(1)).performWithAuditing(auditRecordParamsCaptor.capture(),
            supplierArgumentCaptor.capture());

        Supplier<ResponseEntity<?>> action = supplierArgumentCaptor.getValue();
        assertThat(action.get().getStatusCode(), equalTo(HttpStatus.NOT_FOUND));
        assertThat(auditRecordParamsCaptor.getValue().getOperationCode(),
            equalTo(CREDENTIAL_UPDATE));
      });
    });

    describe("when attempting to regenerate a non-regenerated password", () -> {
      beforeEach(() -> {
        NamedPasswordSecret originalSecret = new NamedPasswordSecret("my-password");
        originalSecret.setEncryptor(encryptor);
        originalSecret.setPasswordAndGenerationParameters("abcde", null);
        doReturn(originalSecret).when(secretDataService).findMostRecent("my-password");

        response = mockMvc.perform(post("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
      });

      it("returns an error", () -> {
        String cannotRegenerateJson = "{\"error\":"
            + " \"The password could not be regenerated because the value was statically set."
            + " Only generated passwords may be regenerated.\"}";

        response.andExpect(content().json(cannotRegenerateJson));
      });

      it("persists an audit entry", () -> {
        ArgumentCaptor<Supplier> supplierArgumentCaptor = ArgumentCaptor.forClass(Supplier.class);
        ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor
            .forClass(AuditRecordBuilder.class);
        verify(auditLogService, times(1)).performWithAuditing(auditRecordParamsCaptor.capture(),
            supplierArgumentCaptor.capture());

        Supplier<ResponseEntity<?>> action = supplierArgumentCaptor.getValue();
        assertThat(action.get().getStatusCode(), equalTo(HttpStatus.BAD_REQUEST));
        assertThat(auditRecordParamsCaptor.getValue().getOperationCode(),
            equalTo(CREDENTIAL_UPDATE));
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
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"regenerate\":true,\"name\":\"my-password\"}"));
          });

          it("returns an error", () -> {
            String cannotRegenerateJson = "{\"error\": "
                + "\"The credential could not be accessed with the provided encryption keys. "
                + "You must update your deployment configuration to continue.\"}";

            response
                .andExpect(status().isInternalServerError())
                .andExpect(content().json(cannotRegenerateJson));
          });
        });
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService)
        .performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
