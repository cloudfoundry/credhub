package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import org.junit.runner.RunWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;

import static com.greghaskins.spectrum.Spectrum.*;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

@RunWith(Spectrum.class)
public class AuditRecordParametersTest {

  private AuditRecordParameters subject;

  {
    describe("with a request", () -> {

      beforeEach(() -> {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/data");
        request.setServerName("host-name");
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "my-header");
        request.addHeader("X-Forwarded-For", "my-header2");
        request.setQueryString("name=foo&first=first_value&second=second_value");
        Authentication authentication = mock(Authentication.class);
        subject = new AuditRecordParameters("foo", request, authentication);
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
  }
}
