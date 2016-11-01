package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.fake.FakePasswordGenerator;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.view.DefaultMapping;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.StaticMapping;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.DefaultTransactionDefinition;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.jayway.jsonassert.impl.matcher.IsCollectionWithSize.hasSize;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test", "FakeUuidGenerator"})
public class SecretsControllerTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  @InjectMocks
  SecretsController subject;

  @Spy
  @Autowired
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @Spy
  @Autowired
  NamedSecretSetHandler namedSecretSetHandler;

  @Spy
  @Autowired
  @InjectMocks
  AuditLogService auditLogService;

  @Spy
  @Autowired
  SecretDataService secretDataService;

  @Autowired
  PlatformTransactionManager transactionManager;
  TransactionStatus transaction;

  @Autowired
  FakeUuidGenerator fakeUuidGenerator;

  @Autowired
  FakePasswordGenerator fakePasswordGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private final String secretName = "my-namespace/subTree/secret-name";

  private ResultActions response;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("generating a secret", () -> {
      it("for a new value secret should return an error message", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"value\"}");

        mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("Credentials of this type cannot be generated. Please adjust the credential type and retry your request."));
      });

      describe("for a new non-value secret", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "\"type\":\"password\"," +
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
              .andExpect(jsonPath("$.value").value(fakePasswordGenerator.getFakePassword()))
              .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor.forClass(NamedPasswordSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedPasswordSecret newPassword = argumentCaptor.getValue();

          assertThat(newPassword.getValue(), equalTo(fakePasswordGenerator.getFakePassword()));
          assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("with an existing secret", () -> {
        beforeEach(() -> {
          final NamedPasswordSecret expectedSecret = new NamedPasswordSecret(secretName, fakePasswordGenerator.getFakePassword());
          doReturn(expectedSecret
              .setUuid(fakeUuidGenerator.makeUuid())
              .setUpdatedAt(frozenTime))
              .when(secretDataService).findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
          resetAuditLogMock();
        });

        describe("with the overwrite flag set to true", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "  \"type\":\"password\"," +
                        "  \"overwrite\":true" +
                        "}");

            response = mockMvc.perform(post);
          });

          it("should return the correct response", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value(fakePasswordGenerator.getFakePassword()))
                .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
                .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
          });

          it("validates parameters", () -> {
            verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
          });

          it("asks the data service to persist the secret", () -> {
            final NamedPasswordSecret namedSecret = (NamedPasswordSecret) secretDataService.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
            assertThat(namedSecret.getValue(), equalTo(fakePasswordGenerator.getFakePassword()));
          });

          it("persists an audit entry", () -> {
            verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"type\":\"password\"}");

            response = mockMvc.perform(post);
          });

          it("should return the expected response", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value(fakePasswordGenerator.getFakePassword()))
                .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
                .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
          });

          it("validates parameters", () -> {
            verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
          });

          it("should not persist the secret", () -> {
            verify(secretDataService, times(0)).save(any(NamedSecret.class));
          });

          it("persists an audit entry", () -> {
            verify(auditLogService).performWithAuditing(eq("credential_access"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });
      });

      it("returns 400 when type is not present", () -> {
        mockMvc.perform(post("/api/v1/data/" + secretName).accept(APPLICATION_JSON))
        .andExpect(status().isBadRequest());
      });
    });

    describe("setting a secret", () -> {
      final String secretValue = "secret-value";

      beforeEach(() -> {
        NamedValueSecret valueSecret = new NamedValueSecret(secretName, secretValue).setUuid(fakeUuidGenerator.makeUuid()).setUpdatedAt(frozenTime);
        doReturn(
            valueSecret
        ).when(secretDataService).save(any(NamedValueSecret.class));

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"" + secretValue + "\"" +
                "}");

        response = mockMvc.perform(put);
      });

      it("returns the secret as json", () -> {
        response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("value"))
            .andExpect(jsonPath("$.value").value(secretValue))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
      });

      it("asks the data service to persist the secret", () -> {
        ArgumentCaptor<NamedValueSecret> argumentCaptor = ArgumentCaptor.forClass(NamedValueSecret.class);

        verify(secretDataService, times(1)).save(argumentCaptor.capture());

        NamedValueSecret namedValueSecret = argumentCaptor.getValue();
        assertThat(namedValueSecret.getValue(), equalTo(secretValue));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
      });

      it("returns 400 when the handler raises an exception", () -> {
        doReturn(
            new NamedValueSecret(secretName, secretValue).setUuid(fakeUuidGenerator.makeUuid()).setUpdatedAt(frozenTime)
        ).when(secretDataService).findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"value\":\"some password\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("The credential type cannot be modified. Please delete the credential if you wish to create it with a different type."));
      });

      it("returns a parameterized error message when json key is invalid", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"response error\":\"invalid key\"," +
                "  \"value\":\"some value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("The request includes an unrecognized parameter 'response error'. Please update or remove this parameter and retry your request."));
      });

      it("returns errors from the auditing service auditing fails", () -> {
        doReturn(new ResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR))
            .when(auditLogService).performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class));

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"some value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isInternalServerError());
      });

      it("allows secrets with '.' in the name", () -> {
        final String testSecretNameWithDot = "test.response";

        mockMvc.perform(put("/api/v1/data/" + testSecretNameWithDot)
            .content("{\"type\":\"value\",\"value\":\"" + "def" + "\"}")
            .contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());
      });
    });

    describe("updating a secret", () -> {
      beforeEach(() -> {
        putSecretInDatabase(secretName, "original value");
        resetAuditLogMock();
      });

      it("should return 400 when trying to update a secret with a mismatching type", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName.toUpperCase())
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"value\":\"my-password\"," +
                "  \"overwrite\":true" +
                "}");
        final String errorMessage = "The credential type cannot be modified. Please delete the credential if you wish to create it with a different type.";
        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(errorMessage));
      });

      describe("with the overwrite flag set to true case-insensitively", () -> {
        final String specialValue = "special value";
        final Spectrum.Value<String> oldUuid = Spectrum.value();

        beforeEach(() -> {
          when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
              .thenReturn(new DefaultMapping() {
                @Override
                public NamedSecret value(NamedSecret namedSecret) {
                  return new NamedValueSecret(namedSecret.getName(), specialValue);
                }
              });

          fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

          final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName.toUpperCase())
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"value\":\"" + specialValue + "\"," +
                  "  \"overwrite\":true" +
                  "}");

          oldUuid.value = fakeUuidGenerator.getLastUuid();

          response = mockMvc.perform(put);
        });

        it("should return the updated value", () -> {
          response
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value(specialValue))
              .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.plusSeconds(10).toString()));
        });

        it("should retain the previous value at the previous id", () -> {
          mockMvc.perform(get("/api/v1/data?id=" + oldUuid.value))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value("original value"))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
        });

        it("should validate requests", () -> {
          when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
              .thenThrow(new ParameterizedValidationException("error.invalid_json_key", newArrayList("$.bogus")));

          final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"value\":\"original value\"," +
                  "  \"overwrite\": true," +
                  "  \"bogus\":\"yargablabla\"" +
                  "}");

          final String errorMessage = "The request includes an unrecognized parameter '$.bogus'. Please update or remove this parameter and retry your request.";
          mockMvc.perform(put)
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value(errorMessage));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("with the overwrite flag set to false", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"value\":\"special value\"" +
                  "}");

          response = mockMvc.perform(put);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value("original value"));
        });

        it("should validate requests", () -> {
          when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
              .thenThrow(new ParameterizedValidationException("error.invalid_json_key", newArrayList("$.bogus")));

          final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName.toUpperCase())
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"value\":\"original value\"," +
                  "  \"overwrite\": false," +
                  "  \"bogus\":\"yargablabla\"" +
                  "}");

          final String errorMessage = "The request includes an unrecognized parameter '$.bogus'. Please update or remove this parameter and retry your request.";
          mockMvc.perform(put)
              .andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value(errorMessage));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_access"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("regenerating a password", () -> {
        beforeEach(() -> {
          when(namedSecretGenerateHandler.make(eq("my-password"), isA(DocumentContext.class)))
              .thenReturn(new StaticMapping(null, new NamedPasswordSecret("my-password", "original"), null, null, null));

          mockMvc.perform(post("/api/v1/data/my-password")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"password\"," +
                  "}"));

          resetAuditLogMock();

          when(namedSecretGenerateHandler.make(eq("my-password"), isA(DocumentContext.class)))
              .thenReturn(new DefaultMapping() {
                @Override
                public NamedSecret password(NamedSecret namedSecret) {
                  ((NamedPasswordSecret) namedSecret).setValue("regenerated");
                  return namedSecret;
                }
              });

          fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

          response = mockMvc.perform(post("/api/v1/data/my-password")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"regenerate\":true}"));
        });

        it("should regenerate the secret", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.value").value("regenerated"))
              .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.plusSeconds(10).toString()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });
    });

    describe("regenerate request for a non-existent secret", () -> {
      it("returns an error", () -> {
        String notFoundJson = "{\"error\": \"Credential not found. Please validate your input and retry your request.\"}";

        response = mockMvc.perform(post("/api/v1/data/my-password")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"regenerate\":true}"))
            .andExpect(content().json(notFoundJson));
      });
    });

    describe("getting a secret", () -> {
      final String secretValue = "my value";

      beforeEach(() -> {
        putSecretInDatabase(secretName, secretValue);
      });

      describe("getting a secret by name case-insensitively (with old-style URLs)", makeGetByNameBlock(secretValue, "/api/v1/data/" + secretName.toUpperCase(), "/api/v1/data/invalid_name"));

      describe("getting a secret by name case-insensitively (with name query param)", makeGetByNameBlock(secretValue, "/api/v1/data?name=" + secretName.toUpperCase(), "/api/v1/data?name=invalid_name"));

      describe("getting a secret by id", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?id=" + fakeUuidGenerator.getLastUuid())
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the secret", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_access"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });
    });

    describe("deleting a secret", () -> {
      it("should return NOT_FOUND when there is no secret with that name", () -> {
        final MockHttpServletRequestBuilder delete = delete("/api/v1/data/invalid_name")
            .accept(APPLICATION_JSON);

        mockMvc.perform(delete)
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("Credential not found. Please validate your input and retry your request."));
      });

      describe("with a transaction", () -> {
        beforeEach(() -> {
          transaction = transactionManager.getTransaction(new DefaultTransactionDefinition());
        });

        afterEach(() -> {
          transactionManager.rollback(transaction);
        });

        describe("when there is one secret with the name (case-insensitive)", () -> {
          beforeEach(() -> {
            secretDataService.save(new NamedPasswordSecret(secretName, "some value"));

            this.response = mockMvc.perform(delete("/api/v1/data/" + secretName.toUpperCase()));
          });

          it("should return a 200 status", () -> {
            this.response.andExpect(status().isOk());
          });

          it("asks data service to remove it from storage", () -> {
            ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
            verify(secretDataService, times(1)).deleteByNameIgnoreCase(argumentCaptor.capture());

            assertThat(argumentCaptor.getValue(), equalTo(secretName.toUpperCase()));
          });

          it("persists an audit entry", () -> {
            verify(auditLogService).performWithAuditing(eq("credential_delete"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });

        describe("when there are multiple secrets with that name", () -> {
          beforeEach(() -> {
            secretDataService.save(new NamedPasswordSecret(secretName, "value1"));
            secretDataService.save(new NamedPasswordSecret(secretName, "value2"));

            this.response = mockMvc.perform(delete("/api/v1/data/" + secretName));
          });

          it("should succeed", () -> {
            this.response.andExpect(status().isOk());
          });

          it("should remove them all from the database", () -> {
            assertThat(secretDataService.findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(secretName).size(), equalTo(0));
          });

          it("persists a single audit entry", () -> {
            verify(auditLogService, times(1)).performWithAuditing(eq("credential_delete"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });
      });
    });

    describe("finding secrets", () -> {
      beforeEach(() -> {
        putSecretInDatabase(secretName, "some value");
      });

      describe("finding credentials by name-like, i.e. partial names, case-insensitively", () -> {
        beforeEach(() -> {
          String substring = secretName.substring(4).toUpperCase();
          doReturn(
              Arrays.asList(new NamedValueSecret(secretName, "some value").setUpdatedAt(frozenTime))
          ).when(secretDataService).findByNameIgnoreCaseContainingOrderByUpdatedAtDesc(substring);
          final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + substring)
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the secret metadata", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials[0].name").value(secretName))
              .andExpect(jsonPath("$.credentials[0].updated_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_find"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("finding credentials by path", () -> {
        beforeEach(() -> {
          String substring = secretName.substring(0, secretName.lastIndexOf("/"));
          doReturn(
              Arrays.asList(new NamedValueSecret(secretName, "some value").setUpdatedAt(frozenTime))
          ).when(secretDataService).findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(substring + "/");

          final String path = substring;
          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the secret metadata", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials[0].name").value(secretName))
              .andExpect(jsonPath("$.credentials[0].updated_at").value(frozenTime.toString()));
        });

        it("should only find paths that start with the specified substring case-independently", () -> {
          final String path = "namespace";

          assertTrue(secretName.contains(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path.toUpperCase())
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(0)));
        });

        it("should return all children which are prefixed with the path case-independently", () -> {
          final String path = "my-namespace";
          doReturn(
              Arrays.asList(new NamedValueSecret(secretName, "some value").setUpdatedAt(frozenTime))
           ).when(secretDataService).findByNameIgnoreCaseStartingWithOrderByUpdatedAtDesc(path.toUpperCase() + "/");

          assertTrue(secretName.startsWith(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path.toUpperCase())
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(1)));
        });

        it("should not findSecretsUsingPath paths which start an existing path but matches incompletely", () -> {
          final String path = "my-namespace/subTr";

          assertTrue(secretName.startsWith(path));

          final MockHttpServletRequestBuilder get = get("/api/v1/data?path=" + path)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get).andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials", hasSize(0)));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_find"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("finding all paths", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?paths=true")
              .accept(APPLICATION_JSON);
          doReturn(
              Arrays.asList("my-namespace/", "my-namespace/subTree/")
          ).when(secretDataService).findAllPaths(true);

          this.response = mockMvc.perform(get);
        });

        it("returns all possible paths for the table of existing credentials", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.paths[0].path").value("my-namespace/"))
              .andExpect(jsonPath("$.paths[1].path").value("my-namespace/subTree/"));
        });
      });
    });
  }

  private Spectrum.Block makeGetByNameBlock(String secretValue, String validUrl, String invalidUrl) {
    return () -> {
      beforeEach(() -> {
        final MockHttpServletRequestBuilder get = get(validUrl)
            .accept(APPLICATION_JSON);

        this.response = mockMvc.perform(get);
      });

      it("should return the secret", () -> {
        this.response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("value"))
            .andExpect(jsonPath("$.value").value(secretValue))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_access"), isA(AuditRecordParameters.class), any(Supplier.class));
      });

      it("returns NOT_FOUND when the secret does not exist", () -> {
        final MockHttpServletRequestBuilder get = get(invalidUrl)
            .accept(APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("Credential not found. Please validate your input and retry your request."));
      });
    };
  }

  private void putSecretInDatabase(String name, String value) throws Exception {
    String uuid = fakeUuidGenerator.makeUuid();
    NamedValueSecret valueSecret = new NamedValueSecret(name, value).setUuid(uuid).setUpdatedAt(frozenTime);
    doReturn(
        valueSecret
    ).when(secretDataService).save(any(NamedValueSecret.class));

    final MockHttpServletRequestBuilder put = put("/api/v1/data/" + name)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"value\":\"" + value + "\"" +
            "}");

    response = mockMvc.perform(put);

    Mockito.reset(secretDataService);
    doReturn(
        valueSecret
    ).when(secretDataService).findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name);
    doReturn(
        valueSecret
    ).when(secretDataService).findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(name.toUpperCase());
    doReturn(
        valueSecret
    ).when(secretDataService).findOneByUuid(uuid);
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(2, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class));
  }
}
