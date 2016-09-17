package io.pivotal.security.controller.v1;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.repository.SecretRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import io.pivotal.security.view.ParameterizedValidationException;
import io.pivotal.security.view.SecretKind;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.uniquify;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
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

import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
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
  SecretRepository secretRepository;

  @Autowired
  FakeUuidGenerator fakeUuidGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private String secretName;

  {
    wireAndUnwire(this);
    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
      secretName = uniquify("my-namespace/secret-name");

      when(auditLogService.performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class)))
          .thenAnswer(invocation -> {
            final Supplier action = invocation.getArgumentAt(2, Supplier.class);
            return action.get();
          });
    });

    describe("generating a secret", () -> {
      beforeEach(() -> {
        when(namedSecretGenerateHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new SecretKind.StaticMapping(new NamedValueSecret(secretName, "some value"), null, null));

        final MockHttpServletRequestBuilder post = post("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"value\"}");

        mockMvc.perform(post)
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("value"))
            .andExpect(jsonPath("$.value").value("some value"))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
      });

      it("validates parameters", () -> {
        verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
      });

      it("persists the secret", () -> {
        final NamedValueSecret namedSecret = (NamedValueSecret) secretRepository.findOneByName(secretName);
        assertThat(namedSecret.getValue(), equalTo("some value"));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
      });
    });

    describe("setting a secret", () -> {
      final String otherValue = "some other value";

      beforeEach(() -> {
        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new SecretKind.StaticMapping(new NamedValueSecret(secretName, otherValue), null, null));

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"" + otherValue + "\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.type").value("value"))
            .andExpect(jsonPath("$.value").value(otherValue))
            .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
            .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
      });

      it("persists the secret", () -> {
        final NamedValueSecret namedSecret = (NamedValueSecret) secretRepository.findOneByName(secretName);
        assertThat(namedSecret.getValue(), equalTo(otherValue));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
      });

      it("preserves secrets when updating without the overwrite flag", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"special value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.value").value("some other value"));
      });

      it("can update a secret", () -> {
        final String specialValue = "special value";

        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenReturn(new DefaultMapping() {
              @Override
              public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
                ((NamedValueSecret) namedSecret).setValue(specialValue);
                return namedSecret;
              }
            });

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"" + specialValue + "\"," +
                "  \"overwrite\":true" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.value").value(specialValue));
      });

      describe("fetching a secret by name", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data/" + secretName)
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(otherValue))
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

      describe("fetching a secret by id", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?id=" + fakeUuidGenerator.getLastUuid())
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(otherValue))
              .andExpect(jsonPath("$.id").value(fakeUuidGenerator.getLastUuid()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_access"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("fetching credentials by name-like (partial names)", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?name-like=" + secretName.substring(4))
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.credentials[0].name").value(secretName))
              .andExpect(jsonPath("$.credentials[0].updated_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_find"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("deleting a secret", () -> {
        beforeEach(() -> {
          mockMvc.perform(delete("/api/v1/data/" + secretName))
              .andExpect(status().isOk());
        });

        it("removes it from storage", () -> {
          assertThat(secretRepository.findOneByName(secretName), nullValue());
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
    });

    describe("overwrite behavior", () -> {
      it("validates parameters of request always, even with overwrite=false", () -> {
          when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
              .thenThrow(new ParameterizedValidationException("error.invalid_json_key", newArrayList("$.bogus")));

        secretRepository.save(new NamedValueSecret(secretName, "anythingReally"));

        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"special value\"," +
                "  \"overwrite\": false," +
                "  \"bogus\":\"yargablabla\"" +
                "}");

        final String errorMessage = "The request includes an unrecognized parameter '$.bogus'. Please update or remove this parameter and retry your request.";
        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(errorMessage));
      });
    });

    it("returns for 400 when the handler raises an exception", () -> {
      when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
          .thenReturn(new DefaultMapping() {
            @Override
            public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
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
            public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
              throw new ParameterizedValidationException("error.invalid_json_key", newArrayList("foo error"));
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
          .andExpect(jsonPath("$.error").value("The request includes an unrecognized parameter 'foo error'. Please update or remove this parameter and retry your request."));
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
      final String testSecretName = uniquify("test");
      final String testSecretNameWithDot = uniquify("test.foo");

      when(namedSecretSetHandler.make(eq(testSecretName), isA(DocumentContext.class)))
          .thenReturn(new SecretKind.StaticMapping(new NamedValueSecret(testSecretName, "abc"), null, null));

      when(namedSecretSetHandler.make(eq(testSecretNameWithDot), isA(DocumentContext.class)))
          .thenReturn(new SecretKind.StaticMapping(new NamedValueSecret(testSecretNameWithDot, "def"), null, null));

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
  }
}