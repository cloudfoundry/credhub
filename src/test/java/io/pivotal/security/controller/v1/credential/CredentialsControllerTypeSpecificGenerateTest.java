package io.pivotal.security.controller.v1.credential;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import com.greghaskins.spectrum.Spectrum.Block;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.credential.Certificate;
import io.pivotal.security.credential.CryptSaltFactory;
import io.pivotal.security.credential.RsaKey;
import io.pivotal.security.credential.SshKey;
import io.pivotal.security.credential.StringCredential;
import io.pivotal.security.credential.User;
import io.pivotal.security.data.CredentialDataService;
import io.pivotal.security.domain.CertificateCredential;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.domain.Credential;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.PasswordCredential;
import io.pivotal.security.domain.RsaCredential;
import io.pivotal.security.domain.SshCredential;
import io.pivotal.security.domain.UserCredential;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.PassayStringCredentialGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.generator.UserGenerator;
import io.pivotal.security.helper.JsonHelper;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.BaseCredentialGenerateRequest;
import io.pivotal.security.request.DefaultCredentialGenerateRequest;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.request.StringGenerationParameters;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.view.AccessControlListResponse;
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

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.AuditingHelper.verifyAuditing;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.request.AccessControlOperation.DELETE;
import static io.pivotal.security.request.AccessControlOperation.READ;
import static io.pivotal.security.request.AccessControlOperation.READ_ACL;
import static io.pivotal.security.request.AccessControlOperation.WRITE;
import static io.pivotal.security.request.AccessControlOperation.WRITE_ACL;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.MultiJsonPathMatcher.multiJsonPath;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class CredentialsControllerTypeSpecificGenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  CredentialDataService credentialDataService;

  @SpyBean
  GenerateService generateService;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @MockBean
  PassayStringCredentialGenerator passwordGenerator;

  @MockBean
  CertificateGenerator certificateGenerator;

  @MockBean
  SshGenerator sshGenerator;

  @MockBean
  RsaGenerator rsaGenerator;

  @MockBean
  UserGenerator userGenerator;

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

  private MockMvc mockMvc;
  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);
  private Consumer<Long> fakeTimeSetter;
  private UUID uuid;

  private final String fakePassword = "generated-credential";
  private final String username = "generated-user";
  private final String publicKey = "public_key";
  private final String certificate = "certificate";
  private final String ca = "ca";
  private final String privateKey = "private_key";
  private final String credentialName = "/my-namespace/subTree/credential-name";
  private ResultActions response;
  private MockHttpServletRequestBuilder post;
  private String fakeSalt;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeSalt = cryptSaltFactory.generateSalt(fakePassword);
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();

      when(passwordGenerator.generateCredential(any(StringGenerationParameters.class)))
          .thenReturn(new StringCredential(fakePassword));

      when(certificateGenerator.generateCredential(any(CertificateParameters.class)))
          .thenReturn(new Certificate(ca, certificate, privateKey, null));

      when(sshGenerator.generateCredential(any(SshGenerationParameters.class)))
          .thenReturn(new SshKey(publicKey, privateKey, null));

      when(rsaGenerator.generateCredential(any(RsaGenerationParameters.class)))
          .thenReturn(new RsaKey(publicKey, privateKey));

      when(userGenerator.generateCredential(any(String.class), any(StringGenerationParameters.class)))
          .thenReturn(new User(username, fakePassword, fakeSalt));
    });

    describe("password", testCredentialBehaviour(
        new Object[]{"$.value", fakePassword},
        "password",
        "{\"exclude_number\": true}",
        (passwordCredential) -> {
          assertThat(passwordCredential.getGenerationParameters().isExcludeNumber(), equalTo(true));
          assertThat(passwordCredential.getPassword(), equalTo(fakePassword));
        },
        () -> new PasswordCredential(credentialName)
            .setEncryptor(encryptor)
            .setPasswordAndGenerationParameters(fakePassword, new StringGenerationParameters().setExcludeNumber(true))
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1))
    ));

    describe("user", testCredentialBehaviour(
      new Object[]{"$.value.username", username,
          "$.value.password", fakePassword},
      "user",
      "null",
      (userCredential) -> {
        assertThat(userCredential.getUsername(), equalTo(username));
        assertThat(userCredential.getPassword(), equalTo(fakePassword));
      },
      () -> new UserCredential(credentialName)
        .setEncryptor(encryptor)
        .setPassword(fakePassword)
        .setUsername(username)
        .setUuid(uuid)
        .setVersionCreatedAt(frozenTime.minusSeconds(1))
    ));

    describe("certificate", testCredentialBehaviour(
        new Object[]{
            "$.value.certificate", "certificate",
            "$.value.private_key", "private_key",
            "$.value.ca", "ca"},
        "certificate",
        "{\"common_name\":\"my-common-name\",\"self_sign\":true}",
        (certificateCredential) -> {
          assertThat(certificateCredential.getCa(), equalTo(ca));
          assertThat(certificateCredential.getCertificate(), equalTo(certificate));
          assertThat(certificateCredential.getPrivateKey(), equalTo(privateKey));
        },
        () -> new CertificateCredential(credentialName)
            .setEncryptor(encryptor)
            .setCa(ca)
            .setCertificate(certificate)
            .setPrivateKey(privateKey)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("ssh", testCredentialBehaviour(
        new Object[]{
            "$.value.public_key", "public_key",
            "$.value.private_key", "private_key",
            "$.value.public_key_fingerprint", null},
        "ssh",
        "null",
        (sshCredential) -> {
          assertThat(sshCredential.getPublicKey(), equalTo(publicKey));
          assertThat(sshCredential.getPrivateKey(), equalTo(privateKey));
        },
        () -> new SshCredential(credentialName)
            .setEncryptor(encryptor)
            .setPrivateKey(privateKey)
            .setPublicKey(publicKey)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );

    describe("rsa", testCredentialBehaviour(
        new Object[]{
            "$.value.public_key", "public_key",
            "$.value.private_key", "private_key"},
        "rsa",
        "null",
        (rsaCredential) -> {
          assertThat(rsaCredential.getPublicKey(), equalTo(publicKey));
          assertThat(rsaCredential.getPrivateKey(), equalTo(privateKey));
        },
        () -> new RsaCredential(credentialName)
            .setEncryptor(encryptor)
            .setPrivateKey(privateKey)
            .setPublicKey(publicKey)
            .setUuid(uuid)
            .setVersionCreatedAt(frozenTime.minusSeconds(1)))
    );
  }

  private <T extends Credential> Block testCredentialBehaviour(
      Object[] typeSpecificResponseFields,
      String credentialType,
      String generationParameters,
      Consumer<T> credentialAssertions,
      Supplier<T> existingCredentialProvider) {
    return () -> {
      describe("for a new credential", () -> {
        beforeEach(() -> {
          post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{" +
                  "\"name\":\"" + credentialName + "\"," +
                  "\"type\":\"" + credentialType + "\"," +
                  "\"parameters\":" + generationParameters + "," +
                  "\"overwrite\":" + false +
                  "}");
        });

        describe("with perform in beforeEach", () -> {
          beforeEach(() -> {
            response = mockMvc.perform(post).andDo(print());
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
            verify(generateService, times(1))
                .performGenerate(
                    isA(EventAuditRecordParameters.class),
                    isA(BaseCredentialGenerateRequest.class),
                    isA(AccessControlEntry.class));
            ArgumentCaptor<Credential> argumentCaptor = ArgumentCaptor.forClass(Credential.class);
            verify(credentialDataService, times(1)).save(argumentCaptor.capture());

            T newCredential = (T) argumentCaptor.getValue();

            credentialAssertions.accept(newCredential);
          });

          it("persists an audit entry", () -> {
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, credentialName, "/api/v1/data", 200);
          });

          it("should create an ACL with the current user having full permissions", () -> {
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
                        asList(READ, WRITE, DELETE, READ_ACL, WRITE_ACL)))));
          });
        });

        it("validates the request body", () -> {
          DefaultCredentialGenerateRequest request = mock(DefaultCredentialGenerateRequest.class);
          doThrow(new ParameterizedValidationException("error.request_validation_test")).when(request).validate();
          doReturn(request).when(objectMapper).readValue(anyString(), any(Class.class));
          response = mockMvc.perform(post)
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
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"" + credentialType + "\"," +
                    "  \"name\":\"" + credentialName + "\"," +
                    "  \"parameters\":" + generationParameters + "," +
                    "  \"overwrite\":true" +
                    "}");

            response = mockMvc.perform(post);
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
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_UPDATE, credentialName, "/api/v1/data", 200);
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{"
                    + "\"type\":\"" + credentialType + "\","
                    + "\"name\":\"" + credentialName + "\","
                    + "\"parameters\":" + generationParameters
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
            verifyAuditing(requestAuditRecordRepository, eventAuditRecordRepository, CREDENTIAL_ACCESS, credentialName, "/api/v1/data", 200);
          });
        });
      });
    };
  }
}
