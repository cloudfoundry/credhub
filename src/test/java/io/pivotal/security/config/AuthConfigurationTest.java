package io.pivotal.security.config;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.INVALID_SCOPE_KEY_JWT;
import static io.pivotal.security.util.AuthConstants.UAA_OAUTH2_PASSWORD_GRANT_TOKEN;
import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT;
import static io.pivotal.security.util.CertificateStringConstants.SELF_SIGNED_CERT_WITH_NO_CLIENT_AUTH_EXT;
import static io.pivotal.security.util.CertificateStringConstants.TEST_CERT_WITHOUT_ORGANIZATION_UNIT;
import static io.pivotal.security.util.CertificateStringConstants.TEST_CERT_WITH_INVALID_ORGANIZATION_UNIT_PREFIX;
import static io.pivotal.security.util.CertificateStringConstants.TEST_CERT_WITH_INVALID_UUID_IN_ORGANIZATION_UNIT;
import static io.pivotal.security.util.X509TestUtil.cert;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(
    value = {"unit-test", "UseRealAuditLogService"},
    resolver = DatabaseProfileResolver.class
)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AuthConfigurationTest {

  @Autowired
  WebApplicationContext applicationContext;


  @MockBean
  SecretDataService secretDataService;


  @MockBean
  RequestAuditRecordDataService requestAuditRecordDataService;

  private MockMvc mockMvc;

  private final String dataApiPath = "/api/v1/data";
  private final String secretName = "test";

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockMvc = MockMvcBuilders
          .webAppContextSetup(applicationContext)
          .apply(springSecurity())
          .build();
      when(requestAuditRecordDataService.save(isA(RequestAuditRecord.class))).thenAnswer(answer -> {
        return answer.getArgumentAt(0, RequestAuditRecord.class);
      });
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
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
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
              .header("Authorization", "Bearer " + INVALID_SCOPE_KEY_JWT)
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isForbidden());
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
        it("allows all client certificates with a valid organizational_unit and client_auth extension",
            () -> {
              final MockHttpServletRequestBuilder post = post(dataApiPath)
                  .with(x509(cert(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
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
              .with(x509(cert(SELF_SIGNED_CERT_WITH_CLIENT_AUTH_EXT)))
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          mockMvc.perform(post)
              .andExpect(status().isOk());

          ArgumentCaptor<RequestAuditRecord> argumentCaptor = ArgumentCaptor.forClass(
              RequestAuditRecord.class
          );
          verify(requestAuditRecordDataService, times(1)).save(argumentCaptor.capture());

          RequestAuditRecord requestAuditRecord = argumentCaptor.getValue();
          assertThat(requestAuditRecord.getClientId(), equalTo(
              "C=US,ST=NY,O=Test Org,OU=app:a12345e5-b2b0-4648-a0d0-772d3d399dcb,CN=example.com,E=test@example.com")
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

        it("denies client certificates without the client_auth extension", () -> {
          final MockHttpServletRequestBuilder post = post(dataApiPath)
              .with(x509(cert(SELF_SIGNED_CERT_WITH_NO_CLIENT_AUTH_EXT)))
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

          final String expectedError = "The provided authentication mechanism does not provide a "
              + "valid identity. Please contact your system administrator.";

          mockMvc.perform(post)
              .andDo(org.springframework.test.web.servlet.result.MockMvcResultHandlers.print())
              .andExpect(status().isUnauthorized())
              .andExpect(jsonPath("$.error")
                  .value( "The provided certificate is not authorized to be used for client authentication."));
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
              .header("Authorization", "Bearer " + UAA_OAUTH2_PASSWORD_GRANT_TOKEN)
              .accept(MediaType.APPLICATION_JSON)
              .contentType(MediaType.APPLICATION_JSON)
              .content("{}");

          mockMvc.perform(post)
              .andExpect(status().isOk());
        });
      });
    });
  }

  private Spectrum.Block withoutAuthCheck(String path, String expectedJsonSpec) {
    return () -> {
      mockMvc.perform(get(path).accept(MediaType.APPLICATION_JSON))
          .andExpect(status().isOk())
          .andExpect(jsonPath(expectedJsonSpec).isNotEmpty());
    };
  }
}
