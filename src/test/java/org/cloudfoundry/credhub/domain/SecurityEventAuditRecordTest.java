package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.util.HashMap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SecurityEventAuditRecordTest {

  private SecurityEventAuditRecord subject;
  private RequestAuditRecord requestAuditRecord;


  @Before
  public void setUp() throws Exception {
    requestAuditRecord = mock(RequestAuditRecord.class);
    subject = new SecurityEventAuditRecord(requestAuditRecord, "actor");
  }

  @Test
  public void determineCs1_whenMTLS_returnsMutualTls() throws Exception {
    when(requestAuditRecord.getAuthMethod()).thenReturn(UserContext.AUTH_METHOD_MUTUAL_TLS);

    assertThat(subject.determineCs1(), equalTo("mutual-tls"));
  }

  @Test
  public void determineCs1_whenoauth_returnsOauthAccessToken() throws Exception {
    when(requestAuditRecord.getAuthMethod()).thenReturn(UserContext.AUTH_METHOD_UAA);

    assertThat(subject.determineCs1(), equalTo("oauth-access-token"));
  }

  @Test
  public void getPathWithQueryParameters_whenThereAreQueryParams() throws Exception {
    when(requestAuditRecord.getQueryParameters()).thenReturn("credential_name=test&actor=test");
    when(requestAuditRecord.getPath()).thenReturn("/api/vi/data");

    assertThat(subject.getPathWithQueryParameters(), equalTo("/api/vi/data?credential_name=test&actor=test"));
  }

  @Test
  public void getPathWithQueryParameters_whenThereAreNotQueryParams() throws Exception {
    when(requestAuditRecord.getQueryParameters()).thenReturn("");
    when(requestAuditRecord.getPath()).thenReturn("/api/vi/data");

    assertThat(subject.getPathWithQueryParameters(), equalTo("/api/vi/data"));
  }

  @Test
  public void getResultCode() throws Exception {
    HashMap<Integer, String> statuses = new HashMap<>();
    statuses.put(100, "info");
    statuses.put(200, "success");
    statuses.put(300, "redirect");
    statuses.put(400, "clientError");
    statuses.put(500, "serverError");

    statuses.forEach((code, status) -> {
      when(requestAuditRecord.getStatusCode()).thenReturn(code);

      assertThat(subject.getResultCode(), equalTo(status));
    });
  }

  @Test
  public void getSignature_returnsTheConcatenationofMethodAndPath() throws Exception {
    when(requestAuditRecord.getMethod()).thenReturn("post");
    when(requestAuditRecord.getPath()).thenReturn("/api/v1/data");

    assertThat(subject.getSignature(), equalTo("post /api/v1/data"));
  }
}
