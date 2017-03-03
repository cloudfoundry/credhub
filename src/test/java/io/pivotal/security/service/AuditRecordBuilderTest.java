package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.OperationAuditRecord;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.entity.AuditingOperationCode.UNKNOWN_OPERATION;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@RunWith(Spectrum.class)
public class AuditRecordBuilderTest {

  {
    describe("with OAuth2 authentication", () -> {
      it("extracts relevant properties from the request", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("GET", "/api/v1/data");
        assertThat(builtRecord.getHostName(), equalTo("host-name"));
        assertThat(builtRecord.getCredentialName(), equalTo("foo"));
        assertThat(builtRecord.getPath(), equalTo("/api/v1/data"));
        assertThat(builtRecord.getRequesterIp(), equalTo("10.0.0.1"));
        assertThat(builtRecord.getXForwardedFor(), equalTo("my-header,my-header2"));
        assertThat(builtRecord.getQueryParameters(), equalTo("name=foo&first=first_value&second=second_value"));
      });

      it("sets operation code to be credential_access for a get request", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("GET", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
      });

      it("sets operation code to be credential_update for a post request", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("POST", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });

      it("sets operation code to be credential_update for a put request", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("PUT", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });

      it("sets operation code to be credential_delete for a delete request", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("DELETE", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
      });

      it("sets operations code to be UNKNOWN_OPERATION in other cases", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("UNRECOGNIZED_HTTP_METHOD", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(UNKNOWN_OPERATION.toString()));
      });

      it("uses the OAuth2Token details to build the OperationAuditRecord", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("GET", "/api/v1/data");

        assertThat(builtRecord.getUserId(), equalTo("TEST_USER_ID"));
        assertThat(builtRecord.getUserName(), equalTo("TEST_USER_NAME"));
        assertThat(builtRecord.getUaaUrl(), equalTo("TEST_UAA_URL"));
        assertThat(builtRecord.getTokenIssued(), equalTo(123L));
        assertThat(builtRecord.getScope(), equalTo("scope1,scope2"));
      });

      it("uses the OAuth2Request details to build the OperationAuditRecord", () -> {
        OperationAuditRecord builtRecord = buildFromOAuth2("GET", "/api/v1/data");

        assertThat(builtRecord.getGrantType(), equalTo("TEST_GRANT_TYPE"));
      });
    });

    describe("with mTLS authentication", () -> {
      it("extracts relevant properties from the request", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("GET", "/api/v1/data");
        assertThat(builtRecord.getHostName(), equalTo("host-name"));
        assertThat(builtRecord.getCredentialName(), equalTo("foo"));
        assertThat(builtRecord.getPath(), equalTo("/api/v1/data"));
        assertThat(builtRecord.getRequesterIp(), equalTo("10.0.0.1"));
        assertThat(builtRecord.getXForwardedFor(), equalTo("my-header,my-header2"));
        assertThat(builtRecord.getQueryParameters(), equalTo("name=foo&first=first_value&second=second_value"));
      });

      it("sets operation code to be credential_access for a get request", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("GET", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
      });

      it("sets operation code to be credential_update for a post request", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("POST", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });

      it("sets operation code to be credential_update for a put request", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("PUT", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });

      it("sets operation code to be credential_delete for a delete request", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("DELETE", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
      });

      it("sets operations code to be UNKNOWN_OPERATION in other cases", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("UNRECOGNIZED_HTTP_METHOD", "/api/v1/data");
        assertThat(builtRecord.getOperation(), equalTo(UNKNOWN_OPERATION.toString()));
      });

      it("specifies that the user was authenticated through MTLS", () -> {
        OperationAuditRecord builtRecord = buildFromMTLS("GET", "/api/v1/data");

        assertThat(builtRecord.getUserId(), equalTo("MTLS"));
        assertThat(builtRecord.getUserName(), equalTo("MTLS"));
        assertThat(builtRecord.getUaaUrl(), equalTo("MTLS"));
        assertThat(builtRecord.getScope(), equalTo("MTLS"));
        assertThat(builtRecord.getGrantType(), equalTo("MTLS"));
        assertThat(builtRecord.getTokenIssued(), equalTo(0L));
      });
    });
  }

  private OperationAuditRecord buildFromMTLS(String method, String url) {
    return build(method, url, mock(PreAuthenticatedAuthenticationToken.class), null);
  }

  private OperationAuditRecord buildFromOAuth2(String method, String url) {
    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    OAuth2Request oAuth2Request = mock(OAuth2Request.class);
    OAuth2AccessToken token = mock(OAuth2AccessToken.class);

    Map<String, Object> additionalInformation = new HashMap<>();
    additionalInformation.put("user_id", "TEST_USER_ID");
    additionalInformation.put("user_name", "TEST_USER_NAME");
    additionalInformation.put("iss", "TEST_UAA_URL");
    additionalInformation.put("iat", 123);

    Set<String> scopes = new HashSet<>();
    scopes.add("scope1");
    scopes.add("scope2");

    when(oAuth2Request.getGrantType()).thenReturn("TEST_GRANT_TYPE");

    when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
    when(token.getAdditionalInformation()).thenReturn(additionalInformation);
    when(token.getExpiration()).thenReturn(Date.from(Instant.ofEpochMilli(123L)));
    when(token.getScope()).thenReturn(scopes);

    return build(method, url, authentication, token);
  }

  private OperationAuditRecord build(String method, String url, Authentication authentication, OAuth2AccessToken token) {
    final Instant timestamp = Instant.ofEpochSecond(12345L);

    MockHttpServletRequest request = new MockHttpServletRequest(method, url);
    request.setServerName("host-name");
    request.setRemoteAddr("10.0.0.1");
    request.addHeader("X-Forwarded-For", "my-header");
    request.addHeader("X-Forwarded-For", "my-header2");
    request.setQueryString("name=foo&first=first_value&second=second_value");

    final AuditRecordBuilder subject = new AuditRecordBuilder("foo", request, authentication);
    subject.setAccessToken(token);

    return subject.build(timestamp);
  }
}
