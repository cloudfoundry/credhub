package org.cloudfoundry.credhub.audit;

import org.springframework.mock.web.MockHttpServletRequest;

import org.cloudfoundry.credhub.utils.StringUtil;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

public class CEFAuditRecordTest {

  private CEFAuditRecord auditRecord;
  private MockHttpServletRequest httpRequest;

  @Before
  public void setUp() {
    this.auditRecord = new CEFAuditRecord();
    this.httpRequest = new MockHttpServletRequest();
    httpRequest.setRequestURI("/foo/bar");
    httpRequest.setQueryString("baz=qux&hi=bye");
    httpRequest.setRemoteAddr("127.0.0.1");
    httpRequest.setServerName("credhub.example");
  }

  @Test
  public void getHttpRequest() {
    httpRequest.setMethod("GET");

    auditRecord.setHttpRequest(httpRequest);
    assertThat(auditRecord.getRequestPath(), is(equalTo("/foo/bar?baz=qux&hi=bye")));
    assertThat(auditRecord.getRequestMethod(), is(equalTo("GET")));
    assertThat(auditRecord.getSignatureId(), is(equalTo("GET /foo/bar")));
    assertThat(auditRecord.getSourceAddress(), equalTo("127.0.0.1"));
    assertThat(auditRecord.getDestinationAddress(), equalTo("credhub.example"));
  }

  @Test
  public void getHttpRequest_setsSourceAddressIfProxied() {
    httpRequest.addHeader("X-FORWARDED-FOR", "192.168.0.1");
    httpRequest.setRemoteAddr("127.0.0.1");
    auditRecord.setHttpRequest(httpRequest);
    assertThat(auditRecord.getSourceAddress(), equalTo("192.168.0.1"));
  }

  @Test
  public void setHttpRequest() {
    final String data = "{\"name\":\"example-value\",\"value\":\"secret\"}";
    httpRequest.setContent(data.getBytes(StringUtil.UTF_8));
    httpRequest.setMethod("PUT");

    auditRecord.setHttpRequest(httpRequest);
    assertThat(auditRecord.getRequestPath(), is(equalTo("/foo/bar?baz=qux&hi=bye")));
    assertThat(auditRecord.getRequestMethod(), is(equalTo("PUT")));
    assertThat(auditRecord.getSignatureId(), is(equalTo("PUT /foo/bar")));
    assertThat(auditRecord.getSourceAddress(), equalTo("127.0.0.1"));
    assertThat(auditRecord.getDestinationAddress(), equalTo("credhub.example"));
  }
}
