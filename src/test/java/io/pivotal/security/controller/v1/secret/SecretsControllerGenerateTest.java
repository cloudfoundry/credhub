package io.pivotal.security.controller.v1.secret;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuditLogTestHelper.resetAuditLogMock;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedCertificateSecret;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedRsaSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.domain.NamedSshSecret;
import io.pivotal.security.generator.BcCertificateGenerator;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.request.AccessControlEntry;
import io.pivotal.security.request.CertificateGenerateRequest;
import io.pivotal.security.request.PasswordGenerateRequest;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.request.RsaGenerateRequest;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerateRequest;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.secret.Password;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.service.AuditLogService;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import io.pivotal.security.util.ExceptionThrowingFunction;
import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerGenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

  @SpyBean
  AuditLogService auditLogService;

  @SpyBean
  SecretDataService secretDataService;

  @SpyBean
  GenerateService generateService;

  @MockBean
  PassayStringSecretGenerator secretGenerator;

  @MockBean
  SshGenerator sshGenerator;

  @MockBean
  RsaGenerator rsaGenerator;

  @MockBean
  BcCertificateGenerator certificateGenerator;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  private MockMvc mockMvc;

  private Instant frozenTime = Instant.ofEpochSecond(1400011001L);

  private Consumer<Long> fakeTimeSetter;

  private final String secretName = "/my-namespace/subTree/secret-name";
  private ResultActions response;
  private UUID uuid;

  private final String fakePassword = "generated-secret";
  private final String publicKey = "public_key";
  private final String privateKey = "private_key";
  private final String cert = "cert";

  private AuditRecordBuilder auditRecordBuilder;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      fakeTimeSetter = mockOutCurrentTimeProvider(mockCurrentTimeProvider);

      fakeTimeSetter.accept(frozenTime.toEpochMilli());
      mockMvc = MockMvcBuilders
          .webAppContextSetup(webApplicationContext)
          .apply(springSecurity())
          .build();
      when(secretGenerator.generateSecret(any(PasswordGenerationParameters.class)))
          .thenReturn(new Password(fakePassword));

      when(sshGenerator.generateSecret(any(SshGenerationParameters.class)))
          .thenReturn(new SshKey(publicKey, privateKey, null));

      when(rsaGenerator.generateSecret(any(RsaGenerationParameters.class)))
          .thenReturn(new RsaKey(publicKey, privateKey));

      when(certificateGenerator.generateSecret(any(CertificateParameters.class)))
          .thenReturn(new Certificate("ca_cert", cert, privateKey));

      auditRecordBuilder = new AuditRecordBuilder();
      resetAuditLogMock(auditLogService, auditRecordBuilder);
    });

    describe("generating a secret", () -> {
      beforeEach(() -> {
        uuid = UUID.randomUUID();
      });

      it("should return an error message for an unknown/garbage type", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"foo\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("The request does not include a valid type. " +
                        "Valid values for generate include 'password', 'certificate', " +
                        "'ssh' and 'rsa'.")
            );
      });

      it("should return an error message for a new value secret", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"value\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("Credentials of this type cannot be generated. " +
                        "Please adjust the credential type and retry your request.")
            );
      });

      it("should return an error message for a new json secret", () -> {
        final MockHttpServletRequestBuilder post = post("/api/v1/data")
            .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
            .accept(APPLICATION_JSON)
            .contentType(APPLICATION_JSON)
            .content("{\"type\":\"json\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post)
            .andExpect(status().isBadRequest())
            .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
            .andExpect(
                jsonPath("$.error")
                    .value("Credentials of this type cannot be generated. " +
                        "Please adjust the credential type and retry your request.")
            );
      });

      describe("when another thread wins a race to write a new value", () -> {
        beforeEach(() -> {
          final NamedPasswordSecret expectedSecret = new NamedPasswordSecret(secretName);
          expectedSecret.setEncryptor(encryptor);
          expectedSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
          expectedSecret.setPasswordAndGenerationParameters(fakePassword, null);

          Mockito.reset(secretDataService);

          doReturn(null)
              .doReturn(expectedSecret
                  .setUuid(uuid)
                  .setVersionCreatedAt(frozenTime.minusSeconds(1))
              ).when(secretDataService).findMostRecent(anyString());

          doThrow(new DataIntegrityViolationException("we already have one of those"))
              .when(secretDataService).save(any(NamedSecret.class));

          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          response = mockMvc.perform(post);
        });

        it("retries and finds the value written by the other thread", () -> {
          verify(secretDataService).save(any(NamedSecret.class));
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.value").value(fakePassword))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(
                  jsonPath("$.version_created_at").value(frozenTime.minusSeconds(1).toString()));
        });
      });

      describe("for a new non-value secret, name in body, not in path", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
              .andExpect(jsonPath("$.value").value(fakePassword))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          verify(generateService, times(1))
              .performGenerate(isA(AuditRecordBuilder.class), isA(PasswordGenerateRequest.class), isA(
                  AccessControlEntry.class));
          ArgumentCaptor<NamedPasswordSecret> argumentCaptor = ArgumentCaptor
              .forClass(NamedPasswordSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedPasswordSecret newPassword = argumentCaptor.getValue();

          assertThat(newPassword.getGenerationParameters().isExcludeNumber(), equalTo(true));
          assertThat(newPassword.getPassword(), equalTo(fakePassword));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
        });
      });

      describe("generate an ssh secret", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(
                  // language=JSON
                  "{\"type\":\"ssh\",\"name\":\"" + secretName + "\",\"parameters\":null}"
              );

          response = mockMvc.perform(post);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("ssh"))
              .andExpect(jsonPath("$.value.public_key").value("public_key"))
              .andExpect(jsonPath("$.value.private_key").value("private_key"))
              .andExpect(jsonPath("$.value.public_key_fingerprint").value(nullValue()))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          verify(generateService, times(1))
              .performGenerate(isA(AuditRecordBuilder.class), isA(SshGenerateRequest.class), isA(AccessControlEntry.class));
          ArgumentCaptor<NamedSshSecret> argumentCaptor = ArgumentCaptor
              .forClass(NamedSshSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedSshSecret newSsh = argumentCaptor.getValue();

          assertThat(newSsh.getPublicKey(), equalTo(publicKey));
          assertThat(newSsh.getPrivateKey(), equalTo(privateKey));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
        });

        it("should not generate SSH secret of invalid length", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(
                  // language=JSON
                  "{\"type\":\"ssh\",\"name\":\"" + secretName
                      + "\",\"parameters\":{\"key_length\" : 1337}}"
              );

          response = mockMvc.perform(post)
              .andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("The provided key length is not supported. "
                          + "Valid values include '2048', '3072' and '4096'.")
              );
        });
      });

      describe("generate a RSA secret", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(
                  // language=JSON
                  "{\"type\":\"rsa\",\"name\":\"" + secretName + "\",\"parameters\":null}"
              );

          response = mockMvc.perform(post);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("rsa"))
              .andExpect(jsonPath("$.value.public_key").value("public_key"))
              .andExpect(jsonPath("$.value.private_key").value("private_key"))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          verify(generateService, times(1))
              .performGenerate(isA(AuditRecordBuilder.class), isA(RsaGenerateRequest.class), isA(AccessControlEntry.class));
          ArgumentCaptor<NamedRsaSecret> argumentCaptor = ArgumentCaptor
              .forClass(NamedRsaSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedRsaSecret newRsa = argumentCaptor.getValue();

          assertThat(newRsa.getPublicKey(), equalTo(publicKey));
          assertThat(newRsa.getPrivateKey(), equalTo(privateKey));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
        });

        it("should not generate RSA secret of invalid length", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(
                  // language=JSON
                  "{\"type\":\"rsa\",\"name\":\"" + secretName
                      + "\",\"parameters\":{\"key_length\" : 1337}}"
              );

          response = mockMvc.perform(post)
              .andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("The provided key length is not supported. "
                          + "Valid values include '2048', '3072' and '4096'.")
              );
        });
      });

      describe("generate a Certificate", () -> {
        beforeEach(() -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content(
                  // language=JSON
                  "{\"type\":\"certificate\",\"name\":\"" + secretName
                      + "\",\"parameters\":{\"common_name\" : \"certificate_common_name\", \"self_sign\": true}}\n"
              );

          response = mockMvc.perform(post);
        });

        it("should return the expected response", () -> {
          response.andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("certificate"))
              .andExpect(jsonPath("$.value.certificate").value(cert))
              .andExpect(jsonPath("$.value.private_key").value(privateKey))
              .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
        });

        it("asks the data service to persist the secret", () -> {
          verify(generateService, times(1))
              .performGenerate(isA(AuditRecordBuilder.class), isA(CertificateGenerateRequest.class), isA(AccessControlEntry.class));
          ArgumentCaptor<NamedCertificateSecret> argumentCaptor = ArgumentCaptor
              .forClass(NamedCertificateSecret.class);
          verify(secretDataService, times(1)).save(argumentCaptor.capture());

          NamedCertificateSecret newCertificate = argumentCaptor.getValue();

          assertThat(newCertificate.getCertificate(), equalTo(cert));
          assertThat(newCertificate.getPrivateKey(), equalTo(privateKey));
        });

        it("persists an audit entry", () -> {
          verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
          assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
        });
      });

      describe("with an existing secret", () -> {
        beforeEach(() -> {
          uuid = UUID.randomUUID();
          final NamedPasswordSecret expectedSecret = new NamedPasswordSecret(secretName);
          expectedSecret.setEncryptor(encryptor);
          expectedSecret.setEncryptionKeyUuid(encryptionKeyCanaryMapper.getActiveUuid());
          expectedSecret.setPasswordAndGenerationParameters(fakePassword, null);
          doReturn(expectedSecret
              .setUuid(uuid)
              .setVersionCreatedAt(frozenTime.minusSeconds(1)))
              .when(secretDataService).findMostRecent(secretName);
          resetAuditLogMock(auditLogService, auditRecordBuilder);
        });

        describe("with the overwrite flag set to true", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{" +
                    "  \"type\":\"password\"," +
                    "  \"name\":\"" + secretName + "\"," +
                    "  \"overwrite\":true" +
                    "}");

            response = mockMvc.perform(post);
          });

          it("should return the correct response", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value(fakePassword))
                .andExpect(jsonPath("$.version_created_at").value(frozenTime.toString()));
          });

          it("asks the data service to persist the secret", () -> {
            final NamedPasswordSecret namedSecret = (NamedPasswordSecret) secretDataService
                .findMostRecent(secretName);
            assertThat(namedSecret.getPassword(), equalTo(fakePassword));
          });

          it("persists an audit entry", () -> {
            verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
            assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
          });
        });

        describe("with the overwrite flag set to false", () -> {
          beforeEach(() -> {
            final MockHttpServletRequestBuilder post = post("/api/v1/data")
                .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
                .accept(APPLICATION_JSON)
                .contentType(APPLICATION_JSON)
                .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

            response = mockMvc.perform(post);
          });

          it("should return the existing values", () -> {
            response.andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(jsonPath("$.type").value("password"))
                .andExpect(jsonPath("$.value").value(fakePassword))
                .andExpect(jsonPath("$.id").value(uuid.toString()))
                .andExpect(
                    jsonPath("$.version_created_at").value(frozenTime.minusSeconds(1).toString()));
          });

          it("should not persist the secret", () -> {
            verify(secretDataService, times(0)).save(any(NamedSecret.class));
          });

          it("persists an audit entry", () -> {
            verify(auditLogService).performWithAuditing(isA(ExceptionThrowingFunction.class));
            assertThat(auditRecordBuilder.getOperationCode(), equalTo(CREDENTIAL_ACCESS));
          });
        });

        it("returns 400 when type is not present", () -> {
          mockMvc.perform(post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .content("{\"name\":\"some-new-secret-name\"}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(
                  jsonPath("$.error")
                      .value("The request does not include a valid type. " +
                          "Valid values for generate include 'password', 'certificate', " +
                          "'ssh' and 'rsa'.")
              );
        });

        it("returns 400 when name is empty", () -> {
          mockMvc.perform(post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"\"}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(
                  jsonPath("$.error")
                      .value("A credential name must be provided. " +
                          "Please validate your input and retry your request.")
              );
        });

        it("returns 400 when name is missing", () -> {
          mockMvc.perform(post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .content("{\"type\":\"password\"}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(
                  jsonPath("$.error")
                      .value("A credential name must be provided. " +
                          "Please validate your input and retry your request.")
              );
        });

        it("returns 400 when incorrect params are sent in request", () -> {
          mockMvc.perform(post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              //language=JSON
              .content("{" +
                  "\"type\":\"password\"," +
                  "\"name\":\"" + secretName + "\"," +
                  "\"parameters\":{" +
                  "\"exclude_number\": true" +
                  "}," +
                  "\"some_unknown_param\": false" +
                  "}")
          )
              .andExpect(status().isBadRequest())
              .andExpect(
                  jsonPath("$.error")
                      .value("The request includes an unrecognized parameter " +
                          "'some_unknown_param'. Please update or remove this parameter and " +
                          "retry your request.")
              );
        });

        it("returns 400 for an unknown/garbage type", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"type\":\"foo\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("The request does not include a valid type. " +
                          "Valid values for generate include 'password', 'certificate', 'ssh' and 'rsa'.")
              );
        });

        it("returns 400 for a new value secret", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"type\":\"value\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("Credentials of this type cannot be generated. " +
                          "Please adjust the credential type and retry your request.")
              );
        });

        it("returns 400 for a new json secret", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/data")
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(APPLICATION_JSON)
              .contentType(APPLICATION_JSON)
              .content("{\"type\":\"json\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isBadRequest())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(
                  jsonPath("$.error")
                      .value("Credentials of this type cannot be generated. " +
                          "Please adjust the credential type and retry your request.")
              );
        });
      });
    });
  }
}
