package io.pivotal.security.controller.v1.secret;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.audit.EventAuditRecordBuilder;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.CertificateParameters;
import io.pivotal.security.domain.Encryptor;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.generator.CertificateGenerator;
import io.pivotal.security.generator.PassayStringSecretGenerator;
import io.pivotal.security.generator.RsaGenerator;
import io.pivotal.security.generator.SshGenerator;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.request.PasswordGenerationParameters;
import io.pivotal.security.request.RsaGenerationParameters;
import io.pivotal.security.request.SshGenerationParameters;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.secret.Password;
import io.pivotal.security.secret.RsaKey;
import io.pivotal.security.secret.SshKey;
import io.pivotal.security.service.EncryptionKeyCanaryMapper;
import io.pivotal.security.service.GenerateService;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
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

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.fit;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@RunWith(Spectrum.class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecretsControllerGenerateTest {

  @Autowired
  WebApplicationContext webApplicationContext;

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
  CertificateGenerator certificateGenerator;

  @Autowired
  EncryptionKeyCanaryMapper encryptionKeyCanaryMapper;

  @Autowired
  private Encryptor encryptor;

  @MockBean
  CurrentTimeProvider mockCurrentTimeProvider;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

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

  private EventAuditRecordBuilder auditRecordBuilder;

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

          fakeTimeSetter.accept(frozenTime.toEpochMilli() + 20);

          response = mockMvc.perform(post).andDo(print());
        });

        fit("retries and finds the value written by the other thread", () -> {
          verify(secretDataService).save(any(NamedSecret.class));
          response
              .andDo(print())
              .andExpect(status().isOk())
              .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.value").value(fakePassword))
              .andExpect(jsonPath("$.id").value(uuid.toString()))
              .andExpect(
                  jsonPath("$.version_created_at").value(frozenTime.minusSeconds(1).toString()));
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
  }
}
