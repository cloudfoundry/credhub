package io.pivotal.security.auth;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static io.pivotal.security.util.AuthConstants.EXPIRED_KEY_JWT;
import static io.pivotal.security.util.AuthConstants.INVALID_JSON_JWT;
import static io.pivotal.security.util.AuthConstants.INVALID_SIGNATURE_JWT;
import static io.pivotal.security.util.CurrentTimeProvider.makeCalendar;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.AuthFailureAuditRecordDataService;
import io.pivotal.security.entity.AuthFailureAuditRecord;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.Map;
import javax.servlet.Filter;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest
public class AuditOAuth2AuthenticationExceptionHandlerTest {

  private final String credentialUrlPath = "/api/v1/data/foo";
  private final String credentialUrlQueryParams = "?my_name=my_value";
  private final String credentialUrl = String.join("", credentialUrlPath, credentialUrlQueryParams);
  @Autowired
  WebApplicationContext applicationContext;
  @Autowired
  Filter springSecurityFilterChain;
  @Autowired
  AuditOAuth2AuthenticationExceptionHandler subject;
  @MockBean
  AuthFailureAuditRecordDataService authFailureAuditRecordDataService;
  @Autowired
  ResourceServerTokenServices tokenServices;
  @MockBean
  CurrentTimeProvider currentTimeProvider;
  private MockMvc mockMvc;

  private final Instant now = Instant.ofEpochSecond(1490903353);

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      when(currentTimeProvider.getInstant()).thenReturn(now);
      when(currentTimeProvider.getNow()).thenReturn(makeCalendar(now.toEpochMilli()));

      mockMvc = MockMvcBuilders
          .webAppContextSetup(applicationContext)
          .addFilter(springSecurityFilterChain)
          .build();
    });

    describe("when the token is invalid", () -> {
      it("logs the 'token_invalid' auth exception to the database", () -> {
        mockMvc.perform(get(credentialUrl)
            .header("Authorization", "Bearer " + INVALID_JSON_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("99.99.99.99");
              return request;
            }));

        ArgumentCaptor<AuthFailureAuditRecord> argumentCaptor = ArgumentCaptor
            .forClass(AuthFailureAuditRecord.class);
        verify(authFailureAuditRecordDataService, times(1)).save(argumentCaptor.capture());

        AuthFailureAuditRecord auditRecord = argumentCaptor.getValue();
        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getAuthMethod(), equalTo(AUTH_METHOD_UAA));
        assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("99.99.99.99"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(),
            equalTo("Cannot convert access token to JSON"));
        assertThat(auditRecord.getUserId(), equalTo(null));
        assertThat(auditRecord.getUserName(), equalTo(null));
        assertThat(auditRecord.getUaaUrl(), equalTo(null));
        assertThat(auditRecord.getAuthValidFrom(), equalTo(-1L));
        assertThat(auditRecord.getAuthValidUntil(), equalTo(-1L));
        assertThat(auditRecord.getClientId(), equalTo(null));
        assertThat(auditRecord.getScope(), equalTo(null));
        assertThat(auditRecord.getGrantType(), equalTo(null));
        assertThat(auditRecord.getMethod(), equalTo("GET"));
        assertThat(auditRecord.getStatusCode(), equalTo(401));
      });
    });

    describe("when the token has been signed with a mismatched RSA key", () -> {
      it("should provide a human-friendly response", () -> {
        String errorMessage = "The request token signature could not be verified. "
            + "Please validate that your request token was issued by the UAA server "
            + "authorized by CredHub.";
        mockMvc.perform(get(credentialUrl)
            .header("Authorization", "Bearer " + INVALID_SIGNATURE_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("invalid_token"))
            .andExpect(jsonPath("$.error_description").value(errorMessage));
      });

      it("logs the 'token_invalid' auth exception to the database", () -> {
        mockMvc.perform(get(credentialUrl)
            .header("Authorization", "Bearer " + INVALID_SIGNATURE_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("99.99.99.99");
              return request;
            }));

        ArgumentCaptor<AuthFailureAuditRecord> argumentCaptor = ArgumentCaptor
            .forClass(AuthFailureAuditRecord.class);
        verify(authFailureAuditRecordDataService, times(1)).save(argumentCaptor.capture());

        AuthFailureAuditRecord auditRecord = argumentCaptor.getValue();
        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getAuthMethod(), equalTo(AUTH_METHOD_UAA));
        assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("99.99.99.99"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(), equalTo(
            "The request token signature could not be verified."
                + " Please validate that your request token was issued by the"
                + " UAA server authorized by CredHub."));
        assertThat(auditRecord.getStatusCode(), equalTo(401));
      });
    });

    describe("when the token is expired", () -> {
      it("returns an 'access_token_expired' error and "
              + "cleans the token from the error_description field",
          () -> {
            mockMvc.perform(get(credentialUrl)
                .header("Authorization", "Bearer " + EXPIRED_KEY_JWT)
                .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("access_token_expired"))
                .andExpect(jsonPath("$.error_description").value("Access token expired"));
          });

      it("saves the 'token_expired' auth exception to the database", () -> {
        mockMvc.perform(get(credentialUrl)
            .header("Authorization", "Bearer " + EXPIRED_KEY_JWT)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("99.99.99.99");
              return request;
            }));

        ArgumentCaptor<AuthFailureAuditRecord> argumentCaptor = ArgumentCaptor
            .forClass(AuthFailureAuditRecord.class);
        verify(authFailureAuditRecordDataService, times(1)).save(argumentCaptor.capture());

        AuthFailureAuditRecord auditRecord = argumentCaptor.getValue();

        assertThat(auditRecord.getNow(), equalTo(now));
        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("99.99.99.99"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(), equalTo("Access token expired"));

        OAuth2AccessToken accessToken = tokenServices.readAccessToken(EXPIRED_KEY_JWT);
        Map<String, Object> additionalInformation = accessToken.getAdditionalInformation();

        assertThat(auditRecord.getUserId(), equalTo(additionalInformation.get("user_id")));
        assertThat(auditRecord.getUserName(), equalTo(additionalInformation.get("user_name")));
        assertThat(auditRecord.getUaaUrl(), equalTo(additionalInformation.get("iss")));
        assertThat(auditRecord.getAuthValidFrom(),
            equalTo(((Number) additionalInformation.get("iat")).longValue())); // 1469051704L
        assertThat(auditRecord.getAuthValidUntil(),
            equalTo(accessToken.getExpiration().toInstant().getEpochSecond())); // 1469051824L
        assertThat(auditRecord.getClientId(), equalTo("credhub_cli"));
        assertThat(auditRecord.getScope(), equalTo("credhub.write,credhub.read"));
        assertThat(auditRecord.getGrantType(), equalTo("password"));
        assertThat(auditRecord.getMethod(), equalTo("GET"));
        assertThat(auditRecord.getStatusCode(), equalTo(401));
      });
    });

    describe("when there is no token provided", () -> {
      it("logs the 'no_token' auth exception to the database", () -> {
        mockMvc.perform(get(credentialUrl)
            .header("X-Forwarded-For", "1.1.1.1,2.2.2.2")
            .accept(MediaType.APPLICATION_JSON)
            .contentType(MediaType.APPLICATION_JSON)
            .with(request -> {
              request.setRemoteAddr("12346");
              return request;
            }));

        ArgumentCaptor<AuthFailureAuditRecord> argumentCaptor = ArgumentCaptor
            .forClass(AuthFailureAuditRecord.class);
        verify(authFailureAuditRecordDataService, times(1)).save(argumentCaptor.capture());

        AuthFailureAuditRecord auditRecord = argumentCaptor.getValue();

        assertThat(auditRecord.getNow(), equalTo(now));
        assertThat(auditRecord.getPath(), equalTo(credentialUrlPath));
        assertThat(auditRecord.getAuthMethod(), equalTo(AUTH_METHOD_UAA));
        assertThat(auditRecord.getQueryParameters(), equalTo("my_name=my_value"));
        assertThat(auditRecord.getOperation(), equalTo("credential_access"));
        assertThat(auditRecord.getRequesterIp(), equalTo("12346"));
        assertThat(auditRecord.getXForwardedFor(), equalTo("1.1.1.1,2.2.2.2"));
        assertThat(auditRecord.getFailureDescription(),
            equalTo("Full authentication is required to access this resource"));
        assertThat(auditRecord.getUserId(), nullValue());
        assertThat(auditRecord.getUserName(), nullValue());
        assertThat(auditRecord.getUaaUrl(), nullValue());
        assertThat(auditRecord.getAuthValidFrom(), equalTo(-1L));
        assertThat(auditRecord.getAuthValidUntil(), equalTo(-1L));
        assertThat(auditRecord.getClientId(), equalTo(null));
        assertThat(auditRecord.getScope(), equalTo(null));
        assertThat(auditRecord.getGrantType(), equalTo(null));
        assertThat(auditRecord.getMethod(), equalTo("GET"));
        assertThat(auditRecord.getStatusCode(), equalTo(401));
      });
    });

    describe("#extractCause", () -> {
      it("extracts a cause from an AuthenticationException", () -> {
        Throwable cause = new Throwable("foo");
        AuthenticationException e = new BadCredentialsException("test", cause);
        assertThat(subject.extractCause(e), equalTo(cause));
      });

      it("extracts the ultimate cause from an AuthenticationException", () -> {
        Throwable cause = new Throwable("foo");
        AuthenticationException e = new BadCredentialsException("test",
            new Exception(new Exception(cause)));
        assertThat(subject.extractCause(e), equalTo(cause));
      });

      it("extracts the ultimate cause from an AuthenticationException", () -> {
        AuthenticationException e = new BadCredentialsException("test");
        assertThat(subject.extractCause(e), equalTo(null));
      });
    });
  }
}
