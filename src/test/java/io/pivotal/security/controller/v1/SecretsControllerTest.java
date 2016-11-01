package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.view.DefaultMapping;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.StaticMapping;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
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
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static com.jayway.jsonassert.impl.matcher.IsCollectionWithSize.hasSize;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
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

  @Mock
  NamedSecretGenerateHandler namedSecretGenerateHandler;

  @Mock
  NamedSecretSetHandler namedSecretSetHandler;

  @Mock
  AuditLogService auditLogService;

  @Autowired
  SecretDataService secretDataService;

  @Autowired
  FakeUuidGenerator fakeUuidGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private String secretName;

  private ResultActions response;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
      secretName = "my-namespace/subTree/secret-name";

      resetAuditLogMock();
    });

    describe("generating a secret", () -> {
      it("for a new value secret should return an error message", () -> {
        when(namedSecretGenerateHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new DefaultMapping() {
              @Override
              public NamedSecret value(NamedSecret namedSecret) {
                throw new ParameterizedValidationException("error.invalid_generate_type");
              }
            });

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
          when(namedSecretGenerateHandler.make(eq(secretName), isA(DocumentContext.class)))
              .thenReturn(new StaticMapping(null, new NamedPasswordSecret(secretName, "some password"), null, null, null));

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
              .andExpect(jsonPath("$.value").value("some password"))
              .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
        });

        it("validates parameters", () -> {
          verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
        });

        it("persists the secret", () -> {
          final NamedPasswordSecret namedSecret = (NamedPasswordSecret) secretDataService.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
          assertThat(namedSecret.getValue(), equalTo("some password"));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("with an existing secret", () -> {
        final String secretValue = "original value";

        beforeEach(() -> {
          putSecretInDatabase(secretValue);
          resetAuditLogMock();
        });

        describe("with the overwrite flag set to true", () -> {
          beforeEach(() -> {
            when(namedSecretGenerateHandler.make(eq(secretName), isA(DocumentContext.class)))
                .thenReturn(new DefaultMapping() {
                  @Override
                  public NamedSecret value(NamedSecret namedSecret) {
                    ((NamedValueSecret) namedSecret).setValue("generated value");
                    return namedSecret;
                  }
                });

            final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                        "  \"type\":\"value\"," +
                        "  \"overwrite\":true" +
                        "}");

            response = mockMvc.perform(post);
          });

          it("should return the correct response", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("value"))
                .andExpect(jsonPath("$.value").value("generated value"))
                .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
                .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
          });

          it("validates parameters", () -> {
            verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
          });

          it("persists the secret", () -> {
            final NamedValueSecret namedSecret = (NamedValueSecret) secretDataService.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
            assertThat(namedSecret.getValue(), equalTo("generated value"));
          });

          it("persists an audit entry", () -> {
            verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            when(namedSecretGenerateHandler.make(eq(secretName), isA(DocumentContext.class)))
                .thenReturn(new StaticMapping(new NamedValueSecret(secretName, "original value"), null, null, null, null));

            final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"type\":\"value\"}");

            response = mockMvc.perform(post);
          });

          it("should return the expected response", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("value"))
                .andExpect(jsonPath("$.value").value("original value"))
                .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
                .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
          });

          it("validates parameters", () -> {
            verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
          });

          it("should not persist the secret", () -> {
            final NamedValueSecret namedSecret = (NamedValueSecret) secretDataService.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
            assertThat(namedSecret.getValue(), equalTo("original value"));
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
      final String secretValue = "some other value";

      beforeEach(() -> {
        putSecretInDatabase(secretValue);
      });

      it("returns the secret as json", () -> {
        response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("value"))
            .andExpect(jsonPath("$.value").value(secretValue))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
      });

      it("persists the secret", () -> {
        final NamedValueSecret namedSecret = (NamedValueSecret) secretDataService.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName);
        assertThat(namedSecret.getValue(), equalTo(secretValue));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
      });

      it("returns 400 when the handler raises an exception", () -> {
        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new DefaultMapping() {
              @Override
              public NamedSecret value(NamedSecret namedSecret) {
                throw new ParameterizedValidationException("error.type_mismatch");
              }
            });

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"some value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("The credential type cannot be modified. Please delete the credential if you wish to create it with a different type."));
      });

      it("returns a parameterized error message when json key is invalid", () -> {
        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new DefaultMapping() {
              @Override
              public NamedSecret value(NamedSecret namedSecret) {
                throw new ParameterizedValidationException("error.invalid_json_key", newArrayList("response error"));
              }
            });

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"some value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("The request includes an unrecognized parameter 'response error'. Please update or remove this parameter and retry your request."));
      });

      it("returns errors from the auditing service auditing fails", () -> {
        when(auditLogService.performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class)))
            .thenReturn(new ResponseEntity(HttpStatus.INTERNAL_SERVER_ERROR));

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
        final String testSecretName = "test";
        final String testSecretNameWithDot = "test.response";

        when(namedSecretSetHandler.make(eq(testSecretName), isA(DocumentContext.class)))
            .thenReturn(new StaticMapping(new NamedValueSecret(testSecretName, "abc"), null, null, null, null));

        when(namedSecretSetHandler.make(eq(testSecretNameWithDot), isA(DocumentContext.class)))
            .thenReturn(new StaticMapping(new NamedValueSecret(testSecretNameWithDot, "def"), null, null, null, null));

        mockMvc.perform(put("/api/v1/data/" + testSecretName)
            .content("{\"type\":\"value\",\"value\":\"" + "abc" + "\"}")
            .contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        mockMvc.perform(put("/api/v1/data/" + testSecretNameWithDot)
            .content("{\"type\":\"value\",\"value\":\"" + "def" + "\"}")
            .contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/data/" + testSecretName))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
            .andExpect(jsonPath("$.value").value("abc"));
      });
    });

    describe("updating a secret", () -> {
      beforeEach(() -> {
        putSecretInDatabase("original value");
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

    describe("getting a secret", () -> {
      final String secretValue = "my value";

      beforeEach(() -> {
        putSecretInDatabase(secretValue);
      });

      describe("getting a secret by name case-insensitively", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data/" + secretName.toUpperCase())
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
          final MockHttpServletRequestBuilder get = get("/api/v1/data/invalid_name")
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().isNotFound())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.error").value("Secret not found. Please validate your input and retry your request."));
        });
      });

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

    describe("deleting a secret case-insensitively", () -> {
      beforeEach(() -> {
        putSecretInDatabase("some value");

        this.response = mockMvc.perform(delete("/api/v1/data/" + secretName.toUpperCase()));
      });

      it("should return a 200 status", () -> {
        this.response.andExpect(status().isOk());
      });

      it("removes it from storage", () -> {
        assertThat(secretDataService.findFirstByNameIgnoreCaseOrderByUpdatedAtDesc(secretName), nullValue());
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_delete"), isA(AuditRecordParameters.class), any(Supplier.class));
      });

      it("returns NOT_FOUND when the secret does not exist", () -> {
        final MockHttpServletRequestBuilder delete = delete("/api/v1/data/invalid_name")
            .accept(APPLICATION_JSON);

        mockMvc.perform(delete)
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("Secret not found. Please validate your input and retry your request."));
      });
    });

    describe("finding secrets", () -> {
      beforeEach(() -> {
        putSecretInDatabase("some value");
      });

      describe("finding credentials by name-like, i.e. partial names, case-insensitively", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + secretName.substring(4).toUpperCase())
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
          final String path = secretName.substring(0, secretName.lastIndexOf("/"));
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
          final String path = secretName.substring(0, secretName.lastIndexOf("/"));
          final MockHttpServletRequestBuilder get = get("/api/v1/data?paths=true")
              .accept(APPLICATION_JSON);

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

  private void putSecretInDatabase(String value) throws Exception {
    when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
        .thenReturn(new StaticMapping(new NamedValueSecret(secretName, value), null, null, null, null));

    final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"value\":\"" + value + "\"" +
            "}");

    response = mockMvc.perform(put);
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    when(auditLogService.performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class)))
        .thenAnswer(invocation -> {
          final Supplier action = invocation.getArgumentAt(2, Supplier.class);
          return action.get();
        });
  }
}
