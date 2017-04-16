package io.pivotal.security.controller.v1.secret;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import com.greghaskins.spectrum.Spectrum.*;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditRecordBuilder;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.*;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseSecretSetRequest;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.SetService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
import net.minidev.json.JSONObject;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.InputStream;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.AuditingHelper.verifyAuditing;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.TestConstants.*;
import static io.pivotal.security.request.AccessControlOperation.*;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.MultiJsonPathMatcher.multiJsonPath;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerTypeSpecificSetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  SecretDataService secretDataService;

  @SpyBean
  SetService setService;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  @SpyBean
  ObjectMapper objectMapper;

  @Autowired
  private Encryptor encryptor;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  private MockMvc mockMvc;
  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);
  private Consumer<Long> fakeTimeSetter;
  private UUID uuid;

  private final String secretName = "/my-namespace/subTree/secret-name";
  private final String password = "test-password";
  private final String certificateValueJsonString = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("ca", TEST_CA)
          .put("certificate", TEST_CERTIFICATE)
          .put("private_key", TEST_PRIVATE_KEY)
          .build());
  private final String sshValueJsonString = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("public_key", SSH_PUBLIC_KEY_4096_WITH_COMMENT)
          .put("private_key", PRIVATE_KEY_4096)
          .build());
  private final String rsaValueJsonString = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("public_key", RSA_PUBLIC_KEY_4096)
          .put("private_key", PRIVATE_KEY_4096)
          .build());
  private final ImmutableMap<String, Integer> nestedValue = ImmutableMap.<String, Integer>builder()
      .put("num", 10)
      .build();
  private final ImmutableMap<String, Object> jsonValueMap = ImmutableMap.<String, Object>builder()
      .put("key", "value")
      .put("fancy", nestedValue)
      .put("array", Arrays.asList("foo", "bar"))
      .build();
  private final String jsonValueJsonString = JSONObject.toJSONString(jsonValueMap);
  private ResultActions response;
  private MockHttpServletRequestBuilder put;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
    });

    describe("value", testSecretBehavior(
        new Object[]{"$.value", password},
        "value",
        "\"" + password + "\"",
        (valueSecret) -> {
          assertThat(valueSecret.getValue(), equalTo(password));
        },
        () -> new NamedValueSecret(secretName)
            .setEncryptor(encryptor)
            .setValue(password)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1))
    ));

    describe("password", testSecretBehavior(
        new Object[]{"$.value", password},
        "password",
        "\"" + password + "\"",
        (passwordSecret) -> {
          assertThat(passwordSecret.getPassword(), equalTo(password));
        },
        () -> new NamedPasswordSecret(secretName)
            .setEncryptor(encryptor)
            .setPasswordAndGenerationParameters(password, null)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1))
    ));

    describe("certificate", testSecretBehavior(
        new Object[]{
            "$.value.certificate", TEST_CERTIFICATE,
            "$.value.private_key", TEST_PRIVATE_KEY,
            "$.value.ca", TEST_CA},
        "certificate",
        certificateValueJsonString,
        (certificateSecret) -> {
          assertThat(certificateSecret.getCa(), equalTo(TEST_CA));
          assertThat(certificateSecret.getCertificate(), equalTo(TEST_CERTIFICATE));
          assertThat(certificateSecret.getPrivateKey(), equalTo(TEST_PRIVATE_KEY));
        },
        () -> new NamedCertificateSecret(secretName)
            .setEncryptor(encryptor)
            .setCa(TEST_CA)

            .setCertificate(TEST_CERTIFICATE)
            .setPrivateKey(TEST_PRIVATE_KEY)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("ssh", testSecretBehavior(
        new Object[]{
            "$.value.public_key", SSH_PUBLIC_KEY_4096_WITH_COMMENT,
            "$.value.private_key", PRIVATE_KEY_4096,
            "$.value.public_key_fingerprint", "UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc"},
        "ssh",
        sshValueJsonString,
        (sshSecret) -> {
          assertThat(sshSecret.getPublicKey(), equalTo(SSH_PUBLIC_KEY_4096_WITH_COMMENT));
          assertThat(sshSecret.getPrivateKey(), equalTo(PRIVATE_KEY_4096));
        },
        () -> new NamedSshSecret(secretName)
            .setEncryptor(encryptor)
            .setPrivateKey(PRIVATE_KEY_4096)
            .setPublicKey(SSH_PUBLIC_KEY_4096_WITH_COMMENT)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("rsa", testSecretBehavior(
        new Object[]{
            "$.value.public_key", RSA_PUBLIC_KEY_4096,
            "$.value.private_key", PRIVATE_KEY_4096},
        "rsa",
        rsaValueJsonString,
        (rsaSecret) -> {
          assertThat(rsaSecret.getPublicKey(), equalTo(RSA_PUBLIC_KEY_4096));
          assertThat(rsaSecret.getPrivateKey(), equalTo(PRIVATE_KEY_4096));
        },
        () -> new NamedRsaSecret(secretName)
            .setEncryptor(encryptor)
            .setPrivateKey(PRIVATE_KEY_4096)
            .setPublicKey(RSA_PUBLIC_KEY_4096)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("json", testSecretBehavior(
        new Object[]{"$.value", jsonValueMap},
        "json",
        jsonValueJsonString,
        (jsonSecret) -> {
          assertThat(jsonSecret.getValue(), equalTo(jsonValueMap));
        },
        () -> new NamedJsonSecret(secretName)
            .setEncryptor(encryptor)
            .setValue(jsonValueMap)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );
  }

  private <T extends NamedSecret> Block testSecretBehavior(
      Object[] typeSpecificResponseFields,
      String secretType,
      String value,
      Consumer<T> namedSecretAssertions,
      Supplier<T> existingSecretProvider) {
    return () -> {
      describe("for a new secret", () -> {
        beforeEach(() -> {
          put = put("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "\"name\":\"" + secretName + "\"," +
                  "\"type\":\"" + secretType + "\"," +
                  "\"value\":" + value + "," +
                  "\"overwrite\":" + false + "," +
                  "\"access_control_entries\": [" +
                  "{\"actor\": \"app1-guid\"," +
                  "\"operations\": [\"read\"]}]" +
                  "}");
        });

        describe("with perform in beforeEach", () -> {
          beforeEach(() -> {
            response = mockMvc.perform(put).andDo(print());
          });

          it("should return the expected response", () -> {
            ArgumentCaptor<NamedSecret> argumentCaptor = ArgumentCaptor.forClass(NamedSecret.class);
            verify(secretDataService, times(1)).save(argumentCaptor.capture());
            response.andExpect(multiJsonPath(typeSpecificResponseFields))
                .andExpect(multiJsonPath(
                    "$.type", secretType,
                    "$.id", argumentCaptor.getValue().getUuid().toString(),
                    "$.version_created_at", frozenTime.toString()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
          });

          it("asks the data service to persist the secret", () -> {
            verify(setService, times(1))
                .performSet(
                    isA(EventAuditRecordBuilder.class),
                    isA(BaseSecretSetRequest.class),
                    isA(AccessControlEntry.class));
            ArgumentCaptor<NamedSecret> argumentCaptor = ArgumentCaptor.forClass(NamedSecret.class);
            verify(secretDataService, times(1)).save(argumentCaptor.capture());

            T newSecret = (T) argumentCaptor.getValue();

            namedSecretAssertions.accept(newSecret);
          });

          it("persists an audit entry", () -> {
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, secretName, 200);
          });

          it("should create ACEs for the current user having full permissions " +
              "and the provided user", () -> {
            response.andExpect(status().isOk());
            MvcResult result = mockMvc.perform(get("/api/v1/acls?credential_name=" + secretName)
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper
                .deserialize(content, AccessControlListResponse.class);

            assertThat(acl.getCredentialName(), equalTo(secretName));
            assertThat(acl.getAccessControlList(), containsInAnyOrder(
                samePropertyValuesAs(
                    new AccessControlEntry("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d",
                        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL))),
                samePropertyValuesAs(
                    new AccessControlEntry("app1-guid",
                        asList(READ)))));
          });
        });

        it("validates the request body", () -> {
          BaseSecretSetRequest request = mock(BaseSecretSetRequest.class);
          doThrow(new ParameterizedValidationException("error.request_validation_test")).when(request).validate();
          doReturn(request).when(objectMapper).readValue(any(InputStream.class), any(JavaType.class));
          response = mockMvc.perform(put)
              .andDo(print())
              .andExpect(status().isBadRequest())
              .andExpect(content().json("{\"error\":\"Request body was validated and ControllerAdvice worked.\"}"));
        });
      });

      describe("with an existing secret", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          doReturn(existingSecretProvider.get()).when(secretDataService).findMostRecent(secretName);
        });

        describe("with the overwrite flag set to true", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"" + secretType + "\"," +
                    "  \"name\":\"" + secretName + "\"," +
                    "  \"value\":" + value + "," +
                    "  \"overwrite\":true" +
                    "}");

            response = mockMvc.perform(put);
          });

          it("should return the correct response", () -> {
            ArgumentCaptor<NamedSecret> argumentCaptor = ArgumentCaptor.forClass(NamedSecret.class);
            verify(secretDataService, times(1)).save(argumentCaptor.capture());

            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(multiJsonPath(typeSpecificResponseFields))
                .andExpect(multiJsonPath(
                    "$.type", secretType,
                    "$.id", argumentCaptor.getValue().getUuid().toString(),
                    "$.version_created_at", frozenTime.toString()));
          });

          it("asks the data service to persist the secret", () -> {
            T namedSecret = (T) secretDataService.findMostRecent(secretName);
            namedSecretAssertions.accept(namedSecret);
          });

          it("persists an audit entry", () -> {
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, secretName, 200);
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "\"type\":\"" + secretType + "\","
                    + "\"name\":\"" + secretName + "\","
                    + "\"value\":" + value
                    + "}");

            response = mockMvc.perform(post);
          });

          it("should return the existing values", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(multiJsonPath(typeSpecificResponseFields))
                .andExpect(multiJsonPath(
                    "$.id", uuid.toString(),
                    "$.version_created_at", frozenTime.minusSeconds(1).toString()));
          });

          it("should not persist the secret", () -> {
            verify(secretDataService, times(0)).save(any(NamedSecret.class));
          });

          it("persists an audit entry", () -> {
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_ACCESS, secretName, 200);
          });
        });
      });
    };
  }
}
