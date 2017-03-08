package io.pivotal.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.controller.v1.secret.SecretsController;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedPasswordSecret;
import io.pivotal.security.domain.NamedSecret;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
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

import javax.servlet.Filter;
import java.io.ByteArrayInputStream;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.CertificateStringConstants.SIMPLE_SELF_SIGNED_TEST_CERT;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test", "NoExpirationSymmetricKeySecurityConfiguration"}, resolver = DatabaseProfileResolver.class)
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

  private MockMvc mockMvc;

  private String urlPath;

  private String secretName;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      urlPath = "/api/v1/data";
      secretName = "test";
      mockMvc = MockMvcBuilders
          .webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();

      when(secretDataService.save(any(NamedSecret.class))).thenAnswer(invocation -> {
        NamedPasswordSecret namedPasswordSecret = invocation.getArgumentAt(0, NamedPasswordSecret.class);
        namedPasswordSecret.setUuid(UUID.randomUUID());
        namedPasswordSecret.setVersionCreatedAt(Instant.now());
        return namedPasswordSecret;
      });
    });

    it("/info can be accessed without authentication", withoutAuthCheck("/info", "$.auth-server.url"));

    it("/health can be accessed without authentication", withoutAuthCheck("/health", "$.status"));

    it("denies other endpoints", () -> {
      mockMvc.perform(post(urlPath)
          .accept(MediaType.APPLICATION_JSON)
          .contentType(MediaType.APPLICATION_JSON)
          .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}")
      ).andExpect(status().isUnauthorized());
    });

    describe("with a token accepted by our security config", () -> {
      it("allows access", () -> {
        final MockHttpServletRequestBuilder post = post(urlPath)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.VALID_SYMMETRIC_KEY_JWT)
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
        final MockHttpServletRequestBuilder post = post(urlPath)
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.INVALID_SCOPE_SYMMETRIC_KEY_JWT)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post).andExpect(status().isForbidden());
      });
    });

    describe("without a token", () -> {
      it("disallows access", () -> {
        final MockHttpServletRequestBuilder post = post(urlPath)
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"type\":\"password\",\"name\":\"" + secretName + "\"}");

        mockMvc.perform(post).andExpect(status().isUnauthorized());
      });
    });

    describe("with mutual tls", () -> {
      it("allows all client certificates if provided", () -> {
        final MockHttpServletRequestBuilder post = post(urlPath)
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
    });
  }

  private X509Certificate cert(String string) throws CertificateException, NoSuchProviderException {
    return (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
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
