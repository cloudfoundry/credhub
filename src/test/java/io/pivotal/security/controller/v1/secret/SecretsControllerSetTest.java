package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.controller.v1.secret.SecretsController;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedValueSecret;
import io.pivotal.security.fake.FakeUuidGenerator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
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
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class SecretsControllerSetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  @InjectMocks
  SecretsController subject;

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
  FakeUuidGenerator fakeUuidGenerator;

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
        ).when(secretDataService).findMostRecent(secretName);

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

      it("allows secret with '.' in the name", () -> {
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

      it("should validate requests", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data/" + secretName)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"value\":\"original value\"," +
                "  \"bogus\":\"yargablabla\"" +
                "}");

        final String errorMessage = "The request includes an unrecognized parameter 'bogus'. Please update or remove this parameter and retry your request.";
        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(errorMessage));
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

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_access"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });
    });
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
    ).when(secretDataService).findMostRecent(name);
    doReturn(
        valueSecret
    ).when(secretDataService).findMostRecent(name.toUpperCase());
    doReturn(
        valueSecret
    ).when(secretDataService).findByUuid(uuid);
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(2, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class));
  }
}
