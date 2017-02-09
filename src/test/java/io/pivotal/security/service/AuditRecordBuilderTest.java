package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import static com.greghaskins.spectrum.Spectrum.*;
import static io.pivotal.security.entity.AuditingOperationCode.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class AuditRecordBuilderTest {

  private AuditRecordBuilder subject;

  {
    describe("with a request", () -> {

      beforeEach(() -> {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/data");
        request.setServerName("host-name");
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "my-header");
        request.addHeader("X-Forwarded-For", "my-header2");
        request.setQueryString("name=foo&first=first_value&second=second_value");
        Authentication authentication = mock(OAuth2Authentication.class);
        subject = new AuditRecordBuilder("foo", request, authentication);
      });

      it("extracts relevant properties", () -> {
        assertThat(subject.getHostName(), equalTo("host-name"));
        assertThat(subject.getCredentialName(), equalTo("foo"));
        assertThat(subject.getPath(), equalTo("/api/v1/data"));
        assertThat(subject.getRequesterIp(), equalTo("10.0.0.1"));
        assertThat(subject.getXForwardedFor(), equalTo("my-header,my-header2"));
        assertThat(subject.getQueryParameters(), equalTo("name=foo&first=first_value&second=second_value"));
      });
    });

    it("sets operation code to be credential_access for a get request", () -> {
      MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/data");
      subject = new AuditRecordBuilder("foo", request, null);
      assertThat(subject.getOperationCode(), equalTo(CREDENTIAL_ACCESS));
    });

    it("sets operation code to be credential_update for a post request", () -> {
      MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/data");
      subject = new AuditRecordBuilder("foo", request, null);
      assertThat(subject.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
    });

    it("sets operation code to be credential_update for a put request", () -> {
      MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/api/v1/data");
      subject = new AuditRecordBuilder("foo", request, null);
      assertThat(subject.getOperationCode(), equalTo(CREDENTIAL_UPDATE));
    });

    it("sets operation code to be credential_delete for a delete request", () -> {
      MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/api/v1/data");
      subject = new AuditRecordBuilder("foo", request, null);
      assertThat(subject.getOperationCode(), equalTo(CREDENTIAL_DELETE));
    });

    it("sets operations code to be UNKNOWN_OPERATION in other cases", () -> {
      MockHttpServletRequest request = new MockHttpServletRequest("UNRECOGNIZED_HTTP_METHOD", "/api/v1/data");
      subject = new AuditRecordBuilder("foo", request, null);
      assertThat(subject.getOperationCode(), equalTo(UNKNOWN_OPERATION));
    });
  }
}
