package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedValueSecret;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.apache.commons.lang.StringUtils;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = { "unit-test", "UseRealAuditLogService" }, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerSetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @Autowired
  private Encryptor encryptor;

  @SpyBean
  AuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private final String secretName = "/my-namespace/secretForSetTest/secret-name";

  private ResultActions response;

  private UUID uuid;
  final String secretValue = "secret-value";

  private ResultActions[] responses;

  {
    wireAndUnwire(this);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("setting secrets in parallel", () -> {
      beforeEach(()->{
        responses = new ResultActions[2];

        Thread thread1 = new Thread("thread 1") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + secretName + this.getName() + "\"," +
                    "  \"value\":\"" + secretValue + this.getName() + "\"" +
                    "}");

            try {
              responses[0] = mockMvc.perform(put);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };
        Thread thread2 = new Thread("thread 2") {
          @Override
          public void run() {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"value\"," +
                    "  \"name\":\"" + secretName + this.getName() +"\"," +
                    "  \"value\":\"" + secretValue + this.getName() + "\"" +
                    "}");

            try {
              responses[1] = mockMvc.perform(put);
            } catch (Exception e) {
              e.printStackTrace();
            }
          }
        };

        thread1.start();
        thread2.start();
        thread1.join();
        thread2.join();
      });

      it("test", () -> {
        responses[0].andExpect(jsonPath("$.value").value(secretValue + "thread 1"));
        responses[1].andExpect(jsonPath("$.value").value(secretValue + "thread 2"));
      });
    });

    describe("setting a secret", () -> {
      describe("via parameter in request body", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\":\"" + secretValue + "\"" +
                  "}");

          response = mockMvc.perform(put);
        });

        setSecretBehavior();
      });

      describe("when name does not have a leading slash", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + StringUtils.stripStart(secretName, "/") + "\"," +
                  "  \"value\":\"" + secretValue + "\"" +
                  "}");

          response = mockMvc.perform(put);
        });

        setSecretBehavior();
      });

      describe("when another thread wins a race to write a new value", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();

          NamedValueSecret valueSecret = new NamedValueSecret(secretName);
          valueSecret.setEncryptor(encryptor);
          valueSecret.setValue(secretValue);
          valueSecret.setUuid(uuid);
          valueSecret.setVersionCreatedAt(frozenTime);

          doReturn(null)
              .doReturn(valueSecret)
              .when(secretDataService).findMostRecent(anyString());

          doThrow(new DataIntegrityViolationException("we already have one of those"))
              .when(secretDataService).save(any(NamedSecret.class));

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\":\"" + secretValue + "\"" +
                  "}");

          response = mockMvc.perform(put);
        });

        it("retries and finds the value written by the other thread", () -> {
          verify(secretDataService).save(any(NamedSecret.class));
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });
      });
    });

    describe("updating a secret", () -> {
      beforeEach(() -> {
        putSecretInDatabase(secretName, "original value");
        resetAuditLogMock();
      });

      it("should validate requests", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"name\":\"" + secretName + "\"," +
                "  \"value\":\"original value\"," +
                "  \"bogus\":\"yargablabla\"" +
                "}");

        final String errorMessage = "The request includes an unrecognized parameter 'bogus'. Please update or remove this parameter and retry your request.";
        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value(errorMessage));
      });

      it("should return 400 when trying to update a secret with a mismatching type", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"name\":\"" + secretName.toUpperCase() + "\"," +
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

        beforeEach(() -> {
          fakeTimeSetter.accept(frozenTime.plusSeconds(10).toEpochMilli());

          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + secretName.toUpperCase() + "\"," +
                  "  \"value\":\"" + specialValue + "\"," +
                  "  \"overwrite\":true" +
                  "}");

          response = mockMvc.perform(put);
        });

        it("should return the updated value", () -> {
          ArgumentCaptor<NamedSecret> argumentCaptor = ArgumentCaptor.forClass(NamedSecret.class);

          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          // Because the data service mutates the original entity, the UUID should be set
          // on the original object during the save.
          UUID originalUuid = uuid;
          UUID expectedUuid = argumentCaptor.getValue().getUuid();

          response
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value(specialValue))
              .andExpect(jsonPath("$.id").value(expectedUuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.plusSeconds(10).toString()));

          assertNotNull(expectedUuid);
          assertThat(expectedUuid, not(equalTo(originalUuid)));
        });

        it("should retain the previous value at the previous id", () -> {
          mockMvc.perform(get("/api/v1/data/" + uuid.toString()))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value("original value"))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CREDENTIAL_UPDATE));
        });
      });

      describe("with the overwrite flag set to false", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder put = put("/api/v1/data")
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "  \"type\":\"value\"," +
                  "  \"name\":\"" + secretName + "\"," +
                  "  \"value\":\"special value\"" +
                  "}");

          response = mockMvc.perform(put);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(jsonPath("$.value").value("original value"));
        });

        it("persists an audit entry", () -> {
          ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
          verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

          assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CREDENTIAL_ACCESS));
        });
      });
    });
  }

  // this is extracted while we are supporting both body and path
  private void setSecretBehavior() {
    it("returns the secret as json", () -> {
      NamedSecret expected = secretDataService.findMostRecent(secretName);

      response.andExpect(status().isOk())
          .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
          .andExpect(jsonPath("$.type").value("value"))
          .andExpect(jsonPath("$.value").value(secretValue))
          .andExpect(jsonPath("$.id").value(expected.getUuid().toString()))
          .andExpect(jsonPath("$.version_created_at").value(expected.getVersionCreatedAt().toString()));
    });

    it("asks the data service to persist the secret", () -> {
      ArgumentCaptor<NamedValueSecret> argumentCaptor = ArgumentCaptor.forClass(NamedValueSecret.class);

      verify(secretDataService, times(1)).save(argumentCaptor.capture());

      NamedValueSecret namedValueSecret = argumentCaptor.getValue();
      assertThat(namedValueSecret.getValue(), equalTo(secretValue));
    });

    it("persists an audit entry", () -> {
      ArgumentCaptor<AuditRecordBuilder> auditRecordParamsCaptor = ArgumentCaptor.forClass(AuditRecordBuilder.class);
      verify(auditLogService).performWithAuditing(auditRecordParamsCaptor.capture(), any(Supplier.class));

      assertThat(auditRecordParamsCaptor.getValue().getOperationCode(), equalTo(CREDENTIAL_UPDATE));
    });

    describe("error handling", () -> {
      it("returns 400 when the handler raises an exception", () -> {
        NamedValueSecret namedValueSecret = new NamedValueSecret(secretName);
        namedValueSecret.setEncryptor(encryptor);
        namedValueSecret.setValue(secretValue);
        doReturn(
            namedValueSecret
        ).when(secretDataService).findMostRecent(secretName);

        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"name\":\"" + secretName + "\"," +
                "  \"value\":\"some password\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("The credential type cannot be modified. Please delete the credential if you wish to create it with a different type."));
      });

      it("returns 400 when name is empty", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"name\":\"\"," +
                "  \"value\":\"some password\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("A credential name must be provided. Please validate your input and retry your request."));
      });

      it("returns 400 when name is missing", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"password\"," +
                "  \"value\":\"some password\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error").value("A credential name must be provided. Please validate your input and retry your request."));
      });

      it("returns a parameterized error message when json key is invalid", () -> {
        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"name\":\"" + secretName + "\"," +
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
            .when(auditLogService).performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));

        final MockHttpServletRequestBuilder put = put("/api/v1/data")
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{" +
                "  \"type\":\"value\"," +
                "  \"name\":\"" + secretName + "\"," +
                "  \"value\":\"some value\"" +
                "}");

        mockMvc.perform(put)
            .andExpect(status().isInternalServerError());
      });
    });

    it("allows secret with '.' in the name", () -> {
      final String testSecretNameWithDot = "test.response";

      mockMvc.perform(put("/api/v1/data")
          .content("{\"type\":\"value\",\"name\":\"" + testSecretNameWithDot + "\",\"value\":\"" + "def" + "\"}")
          .contentType(MediaType.APPLICATION_JSON_UTF8))
          .andExpect(status().isOk());
    });
  }

  private void putSecretInDatabase(String name, String value) throws Exception {
    final MockHttpServletRequestBuilder put = put("/api/v1/data")
        .accept(APPLICATION_JSON)
        .contentType(APPLICATION_JSON)
        .content("{" +
            "  \"type\":\"value\"," +
            "  \"name\":\"" + name + "\"," +
            "  \"value\":\"" + value + "\"" +
            "}");

    response = mockMvc.perform(put);

    uuid = secretDataService.findMostRecent(name).getUuid();
    reset(secretDataService);
  }

  private void resetAuditLogMock() throws Exception {
    reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(1, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(AuditRecordBuilder.class), isA(Supplier.class));
  }
}
