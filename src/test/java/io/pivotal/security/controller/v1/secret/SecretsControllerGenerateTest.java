package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.fake.FakeAuditLogService;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.secret.Password;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.apache.commons.lang3.StringUtils;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.controller.v1.secret.SecretsController.API_V1_DATA;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerGenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @SpyBean
  FakeAuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  @MockBean
  PassayStringSecretGenerator secretGenerator;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private Consumer<Long> fakeTimeSetter;

  private final String secretName = "/my-namespace/subTree/secret-name";
  private ResultActions response;
  private UUID uuid;

  private final String fakePassword = "generated-secret";

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
      when(secretGenerator.generateSecret(any(PasswordGenerationParameters.class))).thenReturn(new Password(fakePassword));

      resetAuditLogMock();
    });

    describe("generating a secret", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();

        doAnswer(invocation -> {
          NamedSecret secret = invocation.getArgumentAt(0, NamedSecret.class);
          secret.setUuid(uuid);
          secret.setVersionCreatedAt(frozenTime);
          return secret;
        }).when(secretDataService).save(any(NamedSecret.class));
      });

      it("for an unknown/garbage type should return an error message", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"foo\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("The request does not include a valid type. Valid values for generate include 'password', 'certificate', 'ssh' and 'rsa'."));
      });

      it("for a new value secret should return an error message", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"value\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("Credentials of this type cannot be generated. Please adjust the credential type and retry your request."));
      });

      it("for a new json secret should return an error message", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data")
          .accept(APPLICATION_JSON)
          .contentType(APPLICATION_JSON)
          .content("{\"type\":\"json\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post)
          .andExpect(status().isBadRequest())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.error").value("Credentials of this type cannot be generated. Please adjust the credential type and retry your request."));
      });

      describe("when name does not have a leading slash in the request json", () -> {
        it("should return 200", () -> {
          final MockHttpServletRequestBuilder post = post(API_V1_DATA)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + StringUtils.stripStart(secretName, "/") + "\"}");

          mockMvc.perform(post)
              .andExpect(status().is2xxSuccessful());
        });
      });

      describe("for a new non-value secret, name in body, not in path", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "\"type\":\"password\"," +
                  "\"name\":\"" + secretName + "\"," +
                  "\"parameters\":{" +
                  "\"exclude_number\": true" +
                  "}" +
                  "}");

          response = mockMvc.perform(post);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.value").value(fakePassword))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor.forClass(NamedPasswordSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedPasswordSecret newPassword = argumentCaptor.getValue();

          assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
          assertThat(newPassword.getPassword(), equalTo(fakePassword));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> captor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService, times(1)).performWithAuditing(captor.capture(), any(Supplier.class));
          AuditRecordBuilder auditRecorder = captor.getValue();
          assertThat(auditRecorder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
        });
      });

      describe("with an existing secret", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          final NamedPasswordSecret expectedSecret = new NamedPasswordSecret(secretName);
          expectedSecret.setEncryptor(encryptor);
          expectedSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
          expectedSecret.setPasswordAndGenerationParameters(fakePassword, null);
          doReturn(expectedSecret
              .setUuid(uuid)
              .setVersionCreatedAt(frozenTime.minusSeconds(1)))
            .when(secretDataService).findMostRecent(secretName);
          resetAuditLogMock();
        });

        describe("with the overwrite flag set to true", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"name\":\"" + secretName + "\"," +
                    "  \"overwrite\":true" +
                    "}");

            response = mockMvc.perform(post);
          });

          it("should return the correct response", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value(fakePassword))
                .andExpect(jsonPath("$.id").value(uuid.toString()))
                .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
          });

          it("asks the data service to persist the secret", () -> {
            final NamedPasswordSecret namedSecret = (NamedPasswordSecret) secretDataService.findMostRecent(secretName);
            assertThat(namedSecret.getPassword(), equalTo(fakePassword));
          });

          it("persists an audit entry", () -> {
            ArgumentCaptor<AuditRecordBuilder> captor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
            verify(auditLogService, times(1)).performWithAuditing(captor.capture(), any(Supplier.class));
            AuditRecordBuilder auditRecorder = captor.getValue();
            assertThat(auditRecorder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

            response = mockMvc.perform(post);
          });

          it("should return the existing values", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value(fakePassword))
                .andExpect(jsonPath("$.id").value(uuid.toString()))
                .andExpect(jsonPath("$.version_created_at").value(frozenTime.minusSeconds(1).toString()));
          });

          it("should not persist the secret", () -> {
            verify(secretDataService, times(0)).save(any(NamedSecret.class));
          });

          it("persists an audit entry", () -> {
            ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
            verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

            assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CREDENTIAL_ACCESS));
          });
        });

        describe("with bad parameters", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                "  \"type\":\"nopeity mcnope\"," +
                "  \"name\":\"" + secretName + "\"," +
                "  \"overwrite\":true" +
                "}");

            response = mockMvc.perform(post);
          });

          it("returns an error", () -> {
            response.andExpect(status().isBadRequest());
          });
        });
      });

      describe("when another thread wins a race to write a new value", () -> {
        beforeEach(() -> {
          final NamedPasswordSecret expectedSecret = new NamedPasswordSecret(secretName);
          expectedSecret.setEncryptor(encryptor);
          expectedSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
          expectedSecret.setPasswordAndGenerationParameters(fakePassword, null);

          Mockito.reset(secretDataService);

          doReturn(null)
              .doReturn(expectedSecret
                  .setUuid(uuid)
                  .setVersionCreatedAt(frozenTime.minusSeconds(1))
              ).when(secretDataService).findMostRecent(anyString());

          doThrow(new DataIntegrityViolationException("we already have one of those"))
              .when(secretDataService).save(any(NamedSecret.class));

          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          response = mockMvc.perform(post);
        });

        it("retries and finds the value written by the other thread", () -> {
          verify(secretDataService).save(any(NamedSecret.class));
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.value").value(fakePassword))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.minusSeconds(1).toString()));
        });
      });

      describe("error handling", () -> {
        it("returns 400 when type is not present", () -> {
          mockMvc.perform(post("/api/v1/data")
              .accept(APPLICATION_JSON)
              .content("{\"name\":\"some-new-secret-name\"}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value("The request does not include a valid type. Valid values for generate include 'password', 'certificate', 'ssh' and 'rsa'."));
        });

        it("returns 400 when name is empty", () -> {
          mockMvc.perform(post("/api/v1/data")
              .accept(APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"\"}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value("A credential name must be provided. Please validate your input and retry your request."));
        });

        it("returns 400 when name is missing", () -> {
          mockMvc.perform(post("/api/v1/data")
              .accept(APPLICATION_JSON)
              .content("{\"type\":\"password\"}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value("A credential name must be provided. Please validate your input and retry your request."));
        });
      });
    });
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
