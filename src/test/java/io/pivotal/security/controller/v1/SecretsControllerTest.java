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

import javax.validation.ValidationException;
import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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
      secretName = uniquify("secret-name");

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
        when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
            .thenThrow(new UnsupportedOperationException());

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

    it("returns for 400 when the handler raises an exception", () -> {
      when(namedSecretSetHandler.make(eq(secretName), isA(DocumentContext.class)))
          .thenReturn(new DefaultMapping() {
            @Override
            public NamedSecret value(SecretKind secretKind, NamedSecret namedSecret) {
              throw new ValidationException("error.type_mismatch");
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