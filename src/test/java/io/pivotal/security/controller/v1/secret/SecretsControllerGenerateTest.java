package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import com.jayway.jsonpath.DocumentContext;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.NamedPasswordSecret;
import io.pivotal.security.entity.NamedSecret;
import io.pivotal.security.fake.FakePasswordGenerator;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordParameters;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;
import org.springframework.test.context.web.WebAppConfiguration;
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
import static io.pivotal.security.helper.SpectrumHelper.cleanUpAfterTests;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(classes = CredentialManagerApp.class)
@WebAppConfiguration
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles("unit-test")
public class SecretsControllerGenerateTest {

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
  @InjectMocks
  AuditLogService auditLogService;

  @Spy
  @Autowired
  SecretDataService secretDataService;

  @Autowired
  FakePasswordGenerator fakePasswordGenerator;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private final Consumer<Long> fakeTimeSetter;

  private final String secretName = "my-namespace/subTree/secret-name";

  private ResultActions response;
  private UUID uuid;

  {
    wireAndUnwire(this);
    cleanUpAfterTests(this);

    fakeTimeSetter = mockOutCurrentTimeProvider(this);

    beforeEach(() -> {
      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      resetAuditLogMock();
    });

    describe("generating a secret", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();

        doAnswer(invocation -> {
          NamedSecret secret = invocation.getArgumentAt(0, NamedSecret.class);
          secret.setUuid(uuid);
          secret.setUpdatedAt(frozenTime);
          return secret;
        }).when(secretDataService).save(any(NamedSecret.class));
      });

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

      describe("for a new non-value secret, name in path", () -> {
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
              .andExpect(jsonPath("$.id").value(uuid.toString()))
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
              .andExpect(jsonPath("$.value").value(fakePasswordGenerator.getFakePassword()))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor.forClass(NamedPasswordSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedPasswordSecret newPassword = argumentCaptor.getValue();

          assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
          assertThat(newPassword.getValue(), equalTo(fakePasswordGenerator.getFakePassword()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(eq("credential_update"), isA(AuditRecordParameters.class), any(Supplier.class));
        });
      });

      describe("with an existing secret", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          final NamedPasswordSecret expectedSecret = new NamedPasswordSecret(secretName, fakePasswordGenerator.getFakePassword());
          doReturn(expectedSecret
              .setUuid(uuid)
              .setUpdatedAt(frozenTime))
              .when(secretDataService).findMostRecent(secretName);
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
                .andExpect(jsonPath("$.id").value(uuid.toString()))
                .andExpect(jsonPath("$.updated_at").value(frozenTime.toString()));
          });

          it("validates parameters", () -> {
            verify(namedSecretGenerateHandler).make(eq(secretName), any(DocumentContext.class));
          });

          it("asks the data service to persist the secret", () -> {
            final NamedPasswordSecret namedSecret = (NamedPasswordSecret) secretDataService.findMostRecent(secretName);
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
                .andExpect(jsonPath("$.id").value(uuid.toString()))
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
  }

  private void resetAuditLogMock() throws Exception {
    Mockito.reset(auditLogService);
    doAnswer(invocation -> {
      final Supplier action = invocation.getArgumentAt(2, Supplier.class);
      return action.get();
    }).when(auditLogService).performWithAuditing(isA(String.class), isA(AuditRecordParameters.class), isA(Supplier.class));
  }
}
