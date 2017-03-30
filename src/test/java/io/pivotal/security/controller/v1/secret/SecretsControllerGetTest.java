package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.exceptions.KeyNotFoundException;
import io.pivotal.security.fake.FakeAuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.util.ExceptionThrowingFunction;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuditLogTestHelper.resetAuditLogMock;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerGetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @Autowired
  SecretsController subject;

  @SpyBean
  Encryptor encryptor;

  @SpyBean
  FakeAuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private Consumer<Long> fakeTimeSetter;

  private final String secretName = "/my-namespace/controllerGetTest/secret-name";
  private ResultActions response;

  private UUID uuid;

  private AuditRecordBuilder auditRecordBuilder;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();

      auditRecordBuilder = new AuditRecordBuilder();
      resetAuditLogMock(auditLogService, auditRecordBuilder);
    });

    describe("getting a secret", () -> {
      final String secretValue = "my value";

      beforeEach(() -> {
        uuid = UUID.randomUUID();
        NamedValueSecret valueSecret = new NamedValueSecret(secretName)
            .setEncryptor(encryptor)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime);
        valueSecret.setEncryptedValue("fake-encrypted-value1".getBytes());
        valueSecret.setEncryptedValue("fake-encrypted-value2".getBytes());
        NamedValueSecret valueSecret2 = new NamedValueSecret(secretName)
            .setEncryptor(encryptor)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime);
        valueSecret2.setEncryptedValue("fake-encrypted-value2".getBytes());
        valueSecret2.setNonce("fake-nonce2".getBytes());

        doReturn(secretValue).when(encryptor).decrypt(any(UUID.class), any(byte[].class), any(byte[].class));

        doReturn(
            valueSecret
        ).when(secretDataService).findMostRecent(secretName);
        doReturn(
            newArrayList(valueSecret, valueSecret2)
        ).when(secretDataService).findAllByName(secretName.toUpperCase());
        doReturn(
            valueSecret
        ).when(secretDataService).findMostRecent(secretName.toUpperCase());
        doReturn(
            valueSecret
        ).when(secretDataService).findByUuid(uuid.toString());
      });

      describe(
          "case insensitive get secret by name (with name query param, and no leading slash)",
          makeGetByNameBlock(
              secretValue,
              "/api/v1/data?name=" + secretName.toUpperCase(),
          "/api/v1/data?name=invalid_name", "$.data[0]"
          ));

      describe("getting a secret by name when name has multiple leading slashes", () -> {
        it("returns NOT_FOUND", () -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?name=//" + secretName.toUpperCase())
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().isNotFound())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("Credential not found. Please validate your input " +
                          "and retry your request.")
              );
        });
      });

      describe("when passing a 'current' query parameter", () -> {
        it("when true should return only the most recent version", () -> {
          mockMvc.perform(get("/api/v1/data?current=true&name=" + secretName.toUpperCase())
              .accept(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.data", hasSize(1)));

          verify(secretDataService).findMostRecent(secretName.toUpperCase());
        });

        it("when false should return all versions", () -> {
          mockMvc.perform(get("/api/v1/data?current=false&name=" + secretName.toUpperCase())
              .accept(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.data", hasSize(greaterThan(1))));
        });

        it("when omitted should return all versions", () -> {
          mockMvc.perform(get("/api/v1/data?name=" + secretName.toUpperCase())
              .accept(APPLICATION_JSON))
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.data", hasSize(greaterThan(1))));
        });

        it("returns an error when name is not given", () -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data?name=")
              .accept(APPLICATION_JSON);

          mockMvc.perform(get)
              .andExpect(status().is4xxClientError())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("A credential name must be provided. Please " +
                          "validate your input and retry your request.")
              );
        });
      });

      describe("getting a secret by id", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder get = get("/api/v1/data/" + uuid)
              .accept(APPLICATION_JSON);

          this.response = mockMvc.perform(get);
        });

        it("should return the secret", () -> {
          this.response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("value"))
              .andExpect(jsonPath("$.value").value(secretValue))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_ACCESS));
        });
      });
    });

    describe("when key not present", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();
        NamedValueSecret valueSecret =
            new NamedValueSecret(secretName)
                .setEncryptor(encryptor)
                .setUuid(uuid)
                .setVersionCreatedAt(frozenTime);
        valueSecret.setEncryptedValue("fake-encrypted-value1".getBytes());
        valueSecret.setEncryptedValue("fake-encrypted-value2".getBytes());

        doThrow(new KeyNotFoundException())
            .when(encryptor).decrypt(any(UUID.class), any(byte[].class), any(byte[].class));
        doReturn(Arrays.asList(valueSecret)).when(secretDataService).findAllByName(secretName.toUpperCase());
      });

      it("returns KEY_NOT_PRESENT", () -> {
        final MockHttpServletRequestBuilder get =
            get("/api/v1/data?name=" + secretName.toUpperCase())
                .accept(APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isInternalServerError())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath("$.error")
                .value("The credential could not be accessed with the provided" +
                    " encryption keys. You must update your deployment configuration " +
                    "to continue."));
      });
    });
  }

  private Spectrum.Block makeGetByNameBlock(
      String secretValue,
      String validUrl,
      String invalidUrl,
      String jsonPathPrefix
  ) {
    return () -> {
      beforeEach(() -> {
        final MockHttpServletRequestBuilder get = get(validUrl)
            .accept(APPLICATION_JSON);

        this.response = mockMvc.perform(get);
      });

      it("should return the secret", () -> {
        this.response.andExpect(status().isOk())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(jsonPath(jsonPathPrefix + ".type").value("value"))
            .andExpect(jsonPath(jsonPathPrefix + ".value").value(secretValue))
            .andExpect(jsonPath(jsonPathPrefix + ".id").value(uuid.toString()))
            .andExpect(jsonPath(jsonPathPrefix + ".version_created_at").value(frozenTime.toString()));
      });

      it("persists an audit entry", () -> {
        verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
        assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_ACCESS));
      });

      it("returns NOT_FOUND when the secret does not exist", () -> {
        final MockHttpServletRequestBuilder get = get(invalidUrl)
            .accept(APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isNotFound())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("Credential not found. Please validate your input and " +
                        "retry your request.")
            );
      });
    };
  }
}
