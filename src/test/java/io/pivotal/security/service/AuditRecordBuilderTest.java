package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.OperationAuditRecord;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

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
import java.util.Map;

@RunWith(Spectrum.class)
public class AuditRecordBuilderTest {

  {
    describe("with OAuth2 authentication", () -> {
      it("extracts relevant properties from the request", () -> {
        OperationAuditRecord subject = buildOperationAuditRecord("GET", "/api/v1/data");
        assertThat(subject.getHostName(), equalTo("host-name"));
        assertThat(subject.getCredentialName(), equalTo("foo"));
        assertThat(subject.getPath(), equalTo("/api/v1/data"));
        assertThat(subject.getRequesterIp(), equalTo("10.0.0.1"));
        assertThat(subject.getXForwardedFor(), equalTo("my-header,my-header2"));
        assertThat(subject.getQueryParameters(), equalTo("name=foo&first=first_value&second=second_value"));
      });

      it("sets operation code to be credential_access for a get request", () -> {
        OperationAuditRecord subject = buildOperationAuditRecord("GET", "/api/v1/data");
        assertThat(subject.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
      });

      it("sets operation code to be credential_update for a post request", () -> {
        OperationAuditRecord subject = buildOperationAuditRecord("POST", "/api/v1/data");
        assertThat(subject.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });

      it("sets operation code to be credential_update for a put request", () -> {
        OperationAuditRecord subject = buildOperationAuditRecord("PUT", "/api/v1/data");
        assertThat(subject.getOperation(), equalTo(CREDENTIAL_UPDATE.toString()));
      });

      it("sets operation code to be credential_delete for a delete request", () -> {
        OperationAuditRecord subject = buildOperationAuditRecord("DELETE", "/api/v1/data");
        assertThat(subject.getOperation(), equalTo(CREDENTIAL_DELETE.toString()));
      });

      it("sets operations code to be UNKNOWN_OPERATION in other cases", () -> {
        OperationAuditRecord subject = buildOperationAuditRecord("UNRECOGNIZED_HTTP_METHOD", "/api/v1/data");
        assertThat(subject.getOperation(), equalTo(UNKNOWN_OPERATION.toString()));
      });
    });
  }

  private OperationAuditRecord buildOperationAuditRecord(String method, String url) {
    final Instant timestamp = Instant.ofEpochSecond(12345L);

    MockHttpServletRequest request = new MockHttpServletRequest(method, url);
    request.setServerName("host-name");
    request.setRemoteAddr("10.0.0.1");
    request.addHeader("X-Forwarded-For", "my-header");
    request.addHeader("X-Forwarded-For", "my-header2");
    request.setQueryString("name=foo&first=first_value&second=second_value");

    OAuth2Authentication authentication = mock(OAuth2Authentication.class);
    OAuth2AccessToken oAuth2AccessToken = mock(OAuth2AccessToken.class);
    OAuth2Request oAuth2Request = mock(OAuth2Request.class);
    Map<String, Object> additionalInformation = new HashMap<>();
    additionalInformation.put("iat", 12345);

    when(authentication.getOAuth2Request()).thenReturn(oAuth2Request);
    when(oAuth2AccessToken.getAdditionalInformation()).thenReturn(additionalInformation);
    when(oAuth2AccessToken.getExpiration()).thenReturn(Date.from(timestamp));

    final AuditRecordBuilder auditRecordBuilder = new AuditRecordBuilder("foo", request, authentication);
    auditRecordBuilder.setAccessToken(oAuth2AccessToken);

    return auditRecordBuilder.build(timestamp);
  }
}
