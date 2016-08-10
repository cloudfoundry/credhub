package io.pivotal.security.oauth;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.config.NoExpirationSymmetricKeySecurityConfiguration;
import io.pivotal.security.entity.AuthFailureAuditRecord;
import io.pivotal.security.repository.AuthFailureAuditRecordRepository;
import io.pivotal.security.util.InstantFactoryBean;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.config.NoExpirationSymmetricKeySecurityConfiguration.EXPIRED_SYMMETRIC_KEY_JWT;
import static io.pivotal.security.helper.SpectrumHelper.autoTransactional;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import java.time.Instant;
import java.util.Map;

import javax.servlet.Filter;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration
@WebAppConfiguration
@ActiveProfiles({"dev", "AuditOAuth2AuthenticationEntryPointTest"})
public class AuditOAuth2AuthenticationEntryPointTest {

  @Autowired
  WebApplicationContext applicationContext;

  @Autowired
  Filter springSecurityFilterChain;

  @Autowired
  @InjectMocks
  AuditOAuth2AuthenticationEntryPoint subject;

  @Autowired
  AuthFailureAuditRecordRepository auditRecordRepository;

  @Autowired
  ResourceServerTokenServices tokenServices;

  @Mock
  InstantFactoryBean instantFactoryBean;

  MockHttpServletRequestBuilder get;

  private MockMvc mockMvc;

  private Instant now;

  {
    wireAndUnwire(this);
    autoTransactional(this);

    beforeEach(() -> {
      now = Instant.now();
      when(instantFactoryBean.getObject()).thenReturn(now);

      mockMvc = MockMvcBuilders
          .webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    describe("when the token is invalid", () -> {
      beforeEach(() -> {
        get = get("/api/v1/data/test")
            .header("Authorization", "Bearer " + NoExpirationSymmetricKeySecurityConfiguration.INVALID_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });
        mockMvc.perform(get);
      });

      it("logs the 'token_invalid' auth exception to the database", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));
        AuthFailureAuditRecord auditRecord = auditRecordRepository.findAll().get(0);
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/test"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(), equalTo(("Cannot convert access token to JSON")));
        assertThat(auditRecord.getUserId(), equalTo(null));
        assertThat(auditRecord.getUserName(), equalTo(null));
        assertThat(auditRecord.getUaaUrl(), equalTo(null));
        assertThat(auditRecord.getTokenIssued(), equalTo(-1L));
        assertThat(auditRecord.getTokenExpires(), equalTo(-1L));
      });
    });

    describe("when the token is expired", () -> {
      beforeEach(() -> {
        get = get("/api/v1/data/foo")
            .header("Authorization", "Bearer " + EXPIRED_SYMMETRIC_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });
        mockMvc.perform(get);
      });

      it("logs the 'token_expired' auth exception to the database", () -> {
        OAuth2AccessToken accessToken = tokenServices.readAccessToken(EXPIRED_SYMMETRIC_KEY_JWT);
        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();

        assertThat(auditRecordRepository.count(), equalTo(1L));
        AuthFailureAuditRecord auditRecord = auditRecordRepository.findAll().get(0);

        assertThat(auditRecord.getNow(), equalTo(now));
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(), equalTo("Access token expired: " + EXPIRED_SYMMETRIC_KEY_JWT));
        assertThat(auditRecord.getUserId(), equalTo(additionalInformation.get("user_id")));
        assertThat(auditRecord.getUserName(), equalTo(additionalInformation.get("user_name")));
        assertThat(auditRecord.getUaaUrl(), equalTo(additionalInformation.get("iss")));
        assertThat(auditRecord.getTokenIssued(), equalTo(((Number) additionalInformation.get("iat")).longValue())); // 1469051704L
        assertThat(auditRecord.getTokenExpires(), equalTo(accessToken.getExpiration().toInstant().getEpochSecond())); // 1469051824L
      });
    });

    describe("when there is no token provided", () -> {
      beforeEach(() -> {
        get = get("/api/v1/data/foo")
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            });
        mockMvc.perform(get);
      });

      it("logs the 'no_token' auth exception to the database", () -> {
        assertThat(auditRecordRepository.count(), equalTo(1L));
        AuthFailureAuditRecord auditRecord = auditRecordRepository.findAll().get(0);

        assertThat(auditRecord.getNow(), equalTo(now));
        assertThat(auditRecord.getPath(), equalTo("/api/v1/data/foo"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(), equalTo("Full authentication is required to access this resource"));
        assertThat(auditRecord.getUserId(), nullValue());
        assertThat(auditRecord.getUserName(), nullValue());
        assertThat(auditRecord.getUaaUrl(), nullValue());
        assertThat(auditRecord.getTokenIssued(), equalTo(-1L));
        assertThat(auditRecord.getTokenExpires(), equalTo(-1L));
      });
    });

  }

  @Configuration
  @Import(CredentialManagerApp.class)
  public static class TestConfiguration {

    @Bean
    @Primary
    @Profile("AuditOAuth2AuthenticationEntryPointTest")
    public JwtAccessTokenConverter symmetricTokenConverter() throws Exception {
      JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
      jwtAccessTokenConverter.setSigningKey("tokenkey");
      jwtAccessTokenConverter.afterPropertiesSet();
      return jwtAccessTokenConverter;
    }
  }
}