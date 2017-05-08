package io.pivotal.security.controller.v1.credential;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.greghaskins.spectrum.Spectrum;
import com.greghaskins.spectrum.Spectrum.Block;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.JsonCredential;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.UserCredential;
import io.pivotal.security.domain.ValueCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.handler.SetRequestHandler;
import io.pivotal.security.helper.AuditingHelper;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialSetRequest;
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

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.ACL_UPDATE;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.MultiJsonPathMatcher.multiJsonPath;
import static io.pivotal.security.util.TestConstants.PRIVATE_KEY_4096;
import static io.pivotal.security.util.TestConstants.RSA_PUBLIC_KEY_4096;
import static io.pivotal.security.util.TestConstants.SSH_PUBLIC_KEY_4096_WITH_COMMENT;
import static io.pivotal.security.util.TestConstants.TEST_CA;
import static io.pivotal.security.util.TestConstants.TEST_CERTIFICATE;
import static io.pivotal.security.util.TestConstants.TEST_PRIVATE_KEY;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
public class CredentialsControllerTypeSpecificSetTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  CredentialDataService credentialDataService;

  @SpyBean
  SetRequestHandler setRequestHandler;

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
  private CryptSaltFactory cryptSaltFactory;

  private AuditingHelper auditingHelper;
  private MockMvc mockMvc;
  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);
  private Consumer<Long> fakeTimeSetter;
  private UUID uuid;

  private final String credentialName = "/my-namespace/subTree/credential-name";
  private final String password = "test-password";
  private final String username = "test-username";
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
  private final String userValueJsonString = JSONObject.toJSONString(
      ImmutableMap.<String, String>builder()
          .put("username", username)
          .put("password", password)
          .build());
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

      auditingHelper = new AuditingHelper(requestAuditRecordRepository, eventAuditRecordRepository);
    });

    describe("value", testCredentialBehaviour(
        new Object[]{"$.value", password},
        "value",
        "\"" + password + "\"",
        (valueCredential) -> {
          assertThat(valueCredential.getValue(), equalTo(password));
        },
        () -> new ValueCredential(credentialName)
            .setEncryptor(encryptor)
            .setValue(password)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1))
    ));

    describe("password", testCredentialBehaviour(
        new Object[]{"$.value", password},
        "password",
        "\"" + password + "\"",
        (passwordCredential) -> {
          assertThat(passwordCredential.getPassword(), equalTo(password));
        },
        () -> new PasswordCredential(credentialName)
            .setEncryptor(encryptor)
            .setPasswordAndGenerationParameters(password, null)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1))
    ));

    describe("certificate", testCredentialBehaviour(
        new Object[]{
            "$.value.certificate", TEST_CERTIFICATE,
            "$.value.private_key", TEST_PRIVATE_KEY,
            "$.value.ca", TEST_CA},
        "certificate",
        certificateValueJsonString,
        (certificateCredential) -> {
          assertThat(certificateCredential.getCa(), equalTo(TEST_CA));
          assertThat(certificateCredential.getCertificate(), equalTo(TEST_CERTIFICATE));
          assertThat(certificateCredential.getPrivateKey(), equalTo(TEST_PRIVATE_KEY));
        },
        () -> new CertificateCredential(credentialName)
            .setEncryptor(encryptor)
            .setCa(TEST_CA)

            .setCertificate(TEST_CERTIFICATE)
            .setPrivateKey(TEST_PRIVATE_KEY)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("ssh", testCredentialBehaviour(
        new Object[]{
            "$.value.public_key", SSH_PUBLIC_KEY_4096_WITH_COMMENT,
            "$.value.private_key", PRIVATE_KEY_4096,
            "$.value.public_key_fingerprint", "UmqxK9UJJR4Jrcw0DcwqJlCgkeQoKp8a+HY+0p0nOgc"},
        "ssh",
        sshValueJsonString,
        (sshCredential) -> {
          assertThat(sshCredential.getPublicKey(), equalTo(SSH_PUBLIC_KEY_4096_WITH_COMMENT));
          assertThat(sshCredential.getPrivateKey(), equalTo(PRIVATE_KEY_4096));
        },
        () -> new SshCredential(credentialName)
            .setEncryptor(encryptor)
            .setPrivateKey(PRIVATE_KEY_4096)
            .setPublicKey(SSH_PUBLIC_KEY_4096_WITH_COMMENT)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("rsa", testCredentialBehaviour(
        new Object[]{
            "$.value.public_key", RSA_PUBLIC_KEY_4096,
            "$.value.private_key", PRIVATE_KEY_4096},
        "rsa",
        rsaValueJsonString,
        (rsaCredential) -> {
          assertThat(rsaCredential.getPublicKey(), equalTo(RSA_PUBLIC_KEY_4096));
          assertThat(rsaCredential.getPrivateKey(), equalTo(PRIVATE_KEY_4096));
        },
        () -> new RsaCredential(credentialName)
            .setEncryptor(encryptor)
            .setPrivateKey(PRIVATE_KEY_4096)
            .setPublicKey(RSA_PUBLIC_KEY_4096)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("json", testCredentialBehaviour(
        new Object[]{"$.value", jsonValueMap},
        "json",
        jsonValueJsonString,
        (jsonCredential) -> {
          assertThat(jsonCredential.getValue(), equalTo(jsonValueMap));
        },
        () -> new JsonCredential(credentialName)
            .setEncryptor(encryptor)
            .setValue(jsonValueMap)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("user", testCredentialBehaviour(
        new Object[]{
            "$.value.username", username,
            "$.value.password", password
        },
        "user",
        userValueJsonString,
        (userCredential) -> {
          assertThat(userCredential.getUsername(), equalTo(username));
          assertThat(userCredential.getPassword(), equalTo(password));
        },
        () -> new UserCredential(credentialName)
            .setEncryptor(encryptor)
            .setUsername(username)
            .setPassword(password)
            .setSalt(cryptSaltFactory.generateSalt(password))
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );
  }

  private <T extends Credential> Block testCredentialBehaviour(
      Object[] typeSpecificResponseFields,
      String credentialType,
      String value,
      Consumer<T> credentialAssertions,
      Supplier<T> existingCredentialProvider) {
    return () -> {
      describe("for a new credential", () -> {
        beforeEach(() -> {
          put = put("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "\"name\":\"" + credentialName + "\"," +
                  "\"type\":\"" + credentialType + "\"," +
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
            ArgumentCaptor<Credential> argumentCaptor = ArgumentCaptor.forClass(Credential.class);
            verify(credentialDataService, times(1)).save(argumentCaptor.capture());
            response.andExpect(multiJsonPath(typeSpecificResponseFields))
                .andExpect(multiJsonPath(
                    "$.type", credentialType,
                    "$.id", argumentCaptor.getValue().getUuid().toString(),
                    "$.version_created_at", frozenTime.toString()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON));
          });

          it("asks the data service to persist the credential", () -> {
            verify(setRequestHandler, times(1))
                .handleSetRequest(
                    isA(UserContext.class),
                    any(),
                    isA(BaseCredentialSetRequest.class),
                    isA(AccessControlEntry.class));
            ArgumentCaptor<Credential> argumentCaptor = ArgumentCaptor.forClass(Credential.class);
            verify(credentialDataService, times(1)).save(argumentCaptor.capture());

            T newCredential = (T) argumentCaptor.getValue();

            credentialAssertions.accept(newCredential);
          });

          it("persists an audit entry", () -> {
            auditingHelper.verifyAuditing("uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200, newArrayList(
                new EventAuditRecordParameters(CREDENTIAL_UPDATE, credentialName),
                new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "app1-guid"),
                new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"),
                new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"),
                new EventAuditRecordParameters(ACL_UPDATE, credentialName, DELETE, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"),
                new EventAuditRecordParameters(ACL_UPDATE, credentialName, READ_ACL, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d"),
                new EventAuditRecordParameters(ACL_UPDATE, credentialName, WRITE_ACL, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d")
            ));
          });

          it("should create ACEs for the current user having full permissions " +
              "and the provided user", () -> {
            response.andExpect(status().isOk());
            MvcResult result = mockMvc.perform(get("/api/v1/acls?credential_name=" + credentialName)
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN))
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn();
            String content = result.getResponse().getContentAsString();
            AccessControlListResponse acl = JsonHelper
                .deserialize(content, AccessControlListResponse.class);

            assertThat(acl.getCredentialName(), equalTo(credentialName));
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
          BaseCredentialSetRequest request = mock(BaseCredentialSetRequest.class);
          doThrow(new ParameterizedValidationException("error.request_validation_test")).when(request).validate();
          doReturn(request).when(objectMapper).readValue(any(InputStream.class), any(JavaType.class));
          response = mockMvc.perform(put)
              .andDo(print())
              .andExpect(status().isBadRequest())
              .andExpect(content().json("{\"error\":\"Request body was validated and ControllerAdvice worked.\"}"));
        });
      });

      describe("with an existing credential", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          doReturn(existingCredentialProvider.get()).when(credentialDataService).findMostRecent(credentialName);
        });

        describe("with the overwrite flag set to true", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder put = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"" + credentialType + "\"," +
                    "  \"name\":\"" + credentialName + "\"," +
                    "  \"value\":" + value + "," +
                    "  \"overwrite\":true" +
                    "}");

            response = mockMvc.perform(put);
          });

          it("should return the correct response", () -> {
            ArgumentCaptor<Credential> argumentCaptor = ArgumentCaptor.forClass(Credential.class);
            verify(credentialDataService, times(1)).save(argumentCaptor.capture());

            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(multiJsonPath(typeSpecificResponseFields))
                .andExpect(multiJsonPath(
                    "$.type", credentialType,
                    "$.id", argumentCaptor.getValue().getUuid().toString(),
                    "$.version_created_at", frozenTime.toString()));
          });

          it("asks the data service to persist the credential", () -> {
            T credential = (T) credentialDataService.findMostRecent(credentialName);
            credentialAssertions.accept(credential);
          });

          it("persists an audit entry", () -> {
            auditingHelper.verifyAuditing(CREDENTIAL_UPDATE, credentialName, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200);
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = put("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "\"type\":\"" + credentialType + "\","
                    + "\"name\":\"" + credentialName + "\","
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

          it("should not persist the credential", () -> {
            verify(credentialDataService, times(0)).save(any(Credential.class));
          });

          it("persists an audit entry", () -> {
            auditingHelper.verifyAuditing(CREDENTIAL_ACCESS, credentialName, "uaa-user:df0c1a26-2875-4bf5-baf9-716c6bb5ea6d", "/api/v1/data", 200);
          });
        });
      });
    };
  }
}
