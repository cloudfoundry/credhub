package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.OperationAuditRecord;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_MUTUAL_TLS;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.entity.AuditingOperationCode.UNKNOWN_OPERATION;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
public class AuditRecordBuilderTest {

  {
    describe("with OAuth2 authentication", () -> {
      it("extracts relevant properties from the request", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("GET", "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getHostName(), equalTo("host-name"));
          assertThat(builtRecord.getCredentialName(), equalTo("foo"));
          assertThat(builtRecord.getPath(), equalTo("/api/v1/data"));
          assertThat(builtRecord.getRequesterIp(), equalTo("10.0.0.1"));
          assertThat(builtRecord.getXForwardedFor(), equalTo("my-header,my-header2"));
          assertThat(builtRecord.getQueryParameters(),
              equalTo("name=foo&first=first_value&second=second_value"));
          assertThat(builtRecord.getAuthMethod(), equalTo(AUTH_METHOD_UAA));
          assertThat(builtRecord.getQueryParameters(),
              equalTo("name=foo&first=first_value&second=second_value"));
          assertThat(builtRecord.getAuthMethod(), equalTo("uaa"));
        });
      });

      it("sets operation code to be credential_access for a get request", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("GET", "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
        });
      });

      it("sets operation code to be credential_update for a post request", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("POST", "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
        });
      });

      it("sets operation code to be credential_update for a put request", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("PUT", "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
        });
      });

      it("sets operation code to be credential_delete for a delete request", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("DELETE", "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
        });
      });

      it("sets operations code to be UNKNOWN_OPERATION in other cases", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("UNRECOGNIZED_HTTP_METHOD",
            "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getOperation(), equalTo(UNKNOWN_OPERATION.toString()));
        });
      });

      it("uses the OAuth2Token details to build the OperationAuditRecord", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("GET", "/api/v1/data");

        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getUserId(), equalTo("TEST_USER_ID"));
          assertThat(builtRecord.getUserName(), equalTo("TEST_USER_NAME"));
          assertThat(builtRecord.getUaaUrl(), equalTo("TEST_UAA_URL"));
          assertThat(builtRecord.getScope(), equalTo("scope1,scope2"));
        });
      });

      it("uses the OAuth2Request details to build the OperationAuditRecord", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("GET", "/api/v1/data");

        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getGrantType(), equalTo("TEST_GRANT_TYPE"));
        });
      });

      it("records auth_valid_from and auth_valid_to", () -> {
        Collection<OperationAuditRecord> builtRecords = buildFromOAuth2("GET", "/api/v1/data");
        builtRecords.forEach(builtRecord -> {
          assertThat(builtRecord.getAuthValidFrom(), equalTo(1413495264L));
          assertThat(builtRecord.getAuthValidUntil(), equalTo(1413538464L));
        });
      });

      describe("with mTLS authentication", () -> {
        it("extracts relevant properties from the request", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("GET", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getHostName(), equalTo("host-name"));
            assertThat(builtRecord.getCredentialName(), equalTo("foo"));
            assertThat(builtRecord.getPath(), equalTo("/api/v1/data"));
            assertThat(builtRecord.getRequesterIp(), equalTo("10.0.0.1"));
            assertThat(builtRecord.getXForwardedFor(), equalTo("my-header,my-header2"));
            assertThat(builtRecord.getQueryParameters(),
                equalTo("name=foo&first=first_value&second=second_value"));
            assertThat(builtRecord.getAuthMethod(), equalTo(AUTH_METHOD_MUTUAL_TLS));
            assertThat(builtRecord.getQueryParameters(),
                equalTo("name=foo&first=first_value&second=second_value"));
            assertThat(builtRecord.getAuthMethod(), equalTo("mutual_tls"));
          });
        });

        it("sets operation code to be credential_access for a get request", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("GET", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
          });
        });

        it("sets operation code to be credential_update for a post request", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("POST", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
          });
        });

        it("sets operation code to be credential_update for a put request", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("PUT", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
          });
        });

        it("sets operation code to be credential_delete for a delete request", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("DELETE", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
          });
        });

        it("sets operations code to be UNKNOWN_OPERATION in other cases", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("UNRECOGNIZED_HTTP_METHOD",
              "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getOperation(), equalTo(UNKNOWN_OPERATION.toString()));
          });
        });

        it("specifies that the user was authenticated through MTLS", () -> {
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("GET", "/api/v1/data");

          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getUserId(), equalTo(null));
            assertThat(builtRecord.getUserName(), equalTo(null));
            assertThat(builtRecord.getUaaUrl(), equalTo(null));
            assertThat(builtRecord.getScope(), equalTo(null));
            assertThat(builtRecord.getGrantType(), equalTo(null));
          });
        });

        // make a real cert with expiration, issued at, client_id, etc.

        it("records auth_valid_from and auth_valid_to", () -> {
          // client cert not valid before / after
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("GET", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getAuthValidFrom(), equalTo(1413495264L));
            assertThat(builtRecord.getAuthValidUntil(), equalTo(1413538464L));
          });
        });

        it("records client_id", () -> {
          // cert common name
          Collection<OperationAuditRecord> builtRecords = buildFromMtls("GET", "/api/v1/data");
          builtRecords.forEach(builtRecord -> {
            assertThat(builtRecord.getClientId(), equalTo("some name"));
          });
        });
      });
    });
  }

  private Collection<OperationAuditRecord> buildFromMtls(String method, String url) {
    X509Certificate certificate = mock(X509Certificate.class);
    Principal principal = mock(Principal.class);
    PreAuthenticatedAuthenticationToken token = mock(PreAuthenticatedAuthenticationToken.class);

    when(certificate.getSubjectDN()).thenReturn(principal);
    when(principal.getName()).thenReturn("some name");

    when(certificate.getNotAfter()).thenReturn(Date.from(Instant.ofEpochSecond(1413538464L)));
    when(certificate.getNotBefore()).thenReturn(Date.from(Instant.ofEpochSecond(1413495264L)));
    when(token.getCredentials()).thenReturn(certificate);

    return build(method, url, token, null);
  }

  private Collection<OperationAuditRecord> buildFromOAuth2(String method, String url) {
    Map<String, Object> additionalInformation = new HashMap<>();
    additionalInformation.put("user_id", "TEST_USER_ID");
    additionalInformation.put("user_name", "TEST_USER_NAME");
    additionalInformation.put("iss", "TEST_UAA_URL");
    additionalInformation.put("iat", 1413495264);

    Set<String> scopes = new HashSet<>();
    scopes.add("scope1");
    scopes.add("scope2");

    OAuth2Request oauth2Request = mock(OAuth2Request.class);

    when(oauth2Request.getGrantType()).thenReturn("TEST_GRANT_TYPE");

    OAuth2AccessToken token = mock(OAuth2AccessToken.class);
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);

    when(authentication.getOAuth2Request()).thenReturn(oauth2Request);
    when(token.getAdditionalInformation()).thenReturn(additionalInformation);
    when(token.getExpiration()).thenReturn(Date.from(Instant.ofEpochSecond(1413538464)));
    when(token.getScope()).thenReturn(scopes);

    return build(method, url, authentication, token);
  }

  private Collection<OperationAuditRecord> build(String method, String url, Authentication authentication,
                                                 OAuth2AccessToken token) {
    final Instant timestamp = Instant.ofEpochSecond(12345L);

    MockHttpServletRequest request = new MockHttpServletRequest(method, url);
    request.setServerName("host-name");
    request.setRemoteAddr("10.0.0.1");
    request.addHeader("X-Forwarded-For", "my-header");
    request.addHeader("X-Forwarded-For", "my-header2");
    request.setQueryString("name=foo&first=first_value&second=second_value");

    final AuditRecordBuilder subject = new AuditRecordBuilder("foo", request, authentication);
    when(authentication.getDetails()).thenReturn(mock(OAuth2AuthenticationDetails.class));

    ResourceServerTokenServices tokenService = mock(ResourceServerTokenServices.class);

    when(tokenService.readAccessToken(any())).thenReturn(token);

    return subject.build(timestamp, tokenService);
  }
}
