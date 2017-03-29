package io.pivotal.security.config;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.INVALID_SCOPE_SYMMETRIC_KEY_JWT;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_TOKEN;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static io.pivotal.security.util.CertificateStringConstants.TEST_CERT_WITHOUT_ORGANIZATION_UNIT;
import static io.pivotal.security.util.CertificateStringConstants.TEST_CERT_WITH_INVALID_ORGANIZATION_UNIT_PREFIX;
import static io.pivotal.security.util.CertificateStringConstants.TEST_CERT_WITH_INVALID_UUID_IN_ORGANIZATION_UNIT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.secret.SecretsController;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.UUID;
import javax.servlet.Filter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(
    value = {"unit-test", "UseRealAuditLogService"},
    resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AuthConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  Filter springSecurityFilterChain;

  @Autowired
  ObjectMapper serializingObjectMapper;

  @MockBean
  SecretDataService secretDataService;

  @InjectMocks
  @Autowired
  SecretsController secretsController;

  @MockBean
  OperationAuditRecordDataService operationAuditRecordDataService;

  private MockMvc mockMvc;

  private final String dataApiPath = "/api/v1/data";
  private final String secretName = "test";

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    it("/info can be accessed without authentication",
        withoutAuthCheck("/info", "$.auth-server.url"));

    it("/health can be accessed without authentication", withoutAuthCheck("/health", "$.status"));

    describe("/api/v1/data", () -> {
      beforeEach(() -> {
        when(secretDataService.save(any(NamedSecret.class))).thenAnswer(invocation -> {
          NamedPasswordSecret namedPasswordSecret = invocation
              .getArgumentAt(0, NamedPasswordSecret.class);
          namedPasswordSecret.setUuid(UUID.randomUUID());
          namedPasswordSecret.setVersionCreatedAt(Instant.now());
          return namedPasswordSecret;
        });
      });

      it("denies access without authentication", () -> {
        mockMvc.perform(post(dataApiPath)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}")
        ).andExpect(status().isUnauthorized());
      });

      describe("with a token accepted by our security config", () -> {
        it("allows access", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.version_created_at").exists())
              .andExpect(jsonPath("$.value").exists());
        });
      });

      describe("with a token without sufficient scopes", () -> {
        it("disallows access", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .header("Authorization", "Bearer " + INVALID_SCOPE_SYMMETRIC_KEY_JWT)
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post).andExpect(status().isUnauthorized());
        });
      });

      describe("without a token", () -> {
        it("disallows access", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post).andExpect(status().isUnauthorized());
        });
      });

      describe("with mutual tls", () -> {
        it("allows all client certificates with a valid organizational_unit if provided", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .with(x509(cert(SIMPLE_SELF_SIGNED_TEST_CERT)))
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isOk())
              .andExpect(jsonPath("$.type").value("password"))
              .andExpect(jsonPath("$.version_created_at").exists())
              .andExpect(jsonPath("$.value").exists());
        });

        it("logs the organization_unit from the DN", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .with(x509(cert(SIMPLE_SELF_SIGNED_TEST_CERT)))
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isOk());

          ArgumentCaptor<OperationAuditRecord> argumentCaptor = ArgumentCaptor.forClass(
              OperationAuditRecord.class
          );
          verify(operationAuditRecordDataService, times(1)).save(argumentCaptor.capture());

          OperationAuditRecord operationAuditRecord = argumentCaptor.getValue();
          assertThat(operationAuditRecord.getClientId(), equalTo(
              "CN=test.example.com,OU=app:b67446e5-b2b0-4648-a0d0-772d3d399dcb,L=exampletown")
          );
        });

        it("denies client certificates with an organizational_unit that doesn't contain a V4 UUID",
            () -> {
              final MockHttpServletRequestBuilder post = post(dataApiPath)
                  .with(x509(cert(TEST_CERT_WITH_INVALID_UUID_IN_ORGANIZATION_UNIT)))
                  .accept(MediaType.APPLICATION_JSON)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

              final String expectedError = "The provided authentication mechanism does not "
                  + "provide a valid identity. Please contact your system administrator.";

              mockMvc.perform(post)
                  .andExpect(status().isUnauthorized())
                  .andExpect(jsonPath("$.error").value(expectedError));
            });

        it("denies client certificates with an organizational_unit not prefixed by 'app:'", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .with(x509(cert(TEST_CERT_WITH_INVALID_ORGANIZATION_UNIT_PREFIX)))
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          final String expectedError = "The provided authentication mechanism does not provide a "
              + "valid identity. Please contact your system administrator.";

          mockMvc.perform(post)
              .andExpect(status().isUnauthorized())
              .andExpect(jsonPath("$.error").value(expectedError));
        });

        it("denies client certificates without an organizational_unit", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .with(x509(cert(TEST_CERT_WITHOUT_ORGANIZATION_UNIT)))
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          final String expectedError = "The provided authentication mechanism does not provide a "
              + "valid identity. Please contact your system administrator.";

          mockMvc.perform(post)
              .andExpect(status().isUnauthorized())
              .andExpect(jsonPath("$.error").value(expectedError));
        });
      });
    });

    describe("/api/v1/vcap", () -> {
      it("denies access without authentication", () -> {
        mockMvc.perform(post("/api/v1/vcap")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content("{}")
        ).andExpect(status().isUnauthorized());
      });

      describe("with a token accepted by our security config", () -> {
        it("allows access", () -> {
          final MockHttpServletRequestBuilder post = post("/api/v1/vcap")
              .header("Authorization", "Bearer " + UAA_OAUTH2_TOKEN)
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{}");

          mockMvc.perform(post)
              .andExpect(status().isOk());
        });
      });
    });
  }

  private X509Certificate cert(String string) throws CertificateException, NoSuchProviderException {
    return (X509Certificate) CertificateFactory
        .getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME)
        .generateCertificate(new ByteArrayInputStream(string.getBytes()));
  }

  private Spectrum.Block withoutAuthCheck(String path, String expectedJsonSpec) {
    return () -> {
      mockMvc.perform(get(path).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isOk())
          .andExpect(jsonPath(expectedJsonSpec).isNotEmpty());
    };
  }
}
