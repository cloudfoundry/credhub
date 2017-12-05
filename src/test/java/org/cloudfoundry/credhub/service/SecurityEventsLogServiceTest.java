package org.cloudfoundry.credhub.service;

import org.cloudfoundry.credhub.config.VersionProvider;
import org.cloudfoundry.credhub.domain.SecurityEventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;

import static org.cloudfoundry.credhub.auth.UserContext.AUTH_METHOD_MUTUAL_TLS;
import static org.cloudfoundry.credhub.auth.UserContext.AUTH_METHOD_UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.mockito.Matchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class SecurityEventsLogServiceTest {

  private final Instant now = Instant.now();
  private final String fakeVersion = "FAKE-VERSION";

  private Logger securityEventsLogger;
  private CurrentTimeProvider currentTimeProvider;
  private SecurityEventsLogService subject;

  private VersionProvider versionProvider = mock(VersionProvider.class);

  @Before
  public void beforeEach() {
    securityEventsLogger = mock(Logger.class);
    currentTimeProvider = mock(CurrentTimeProvider.class);

    when(currentTimeProvider.getInstant()).thenReturn(now);
    when(versionProvider.currentVersion()).thenReturn(fakeVersion);

    subject = new SecurityEventsLogService(securityEventsLogger, versionProvider);
  }

  @After
  public void afterEach() {
    SecurityContextHolder.clearContext();
  }

  @Test
  public void log_shouldLogAnOperationAuditRecordToTheSysLogWhenUsingOAuth() {
    RequestAuditRecord requestAuditRecord = makeOperationAuditRecord("foo=bar", AUTH_METHOD_UAA);

    subject.log(new SecurityEventAuditRecord(requestAuditRecord, "actor-id"));

    verify(securityEventsLogger).info(
        "CEF:0|cloud_foundry|credhub|"
            + fakeVersion + "|GET /api/some-path|"
            + "GET /api/some-path|0|rt="
            + String.valueOf(now.toEpochMilli())
            + " suser=user-name "
            + "suid=actor-id "
            + "cs1Label=userAuthenticationMechanism "
            + "cs1=oauth-access-token "
            + "request=/api/some-path?foo=bar "
            + "requestMethod=GET "
            + "cs3Label=result "
            + "cs3=success "
            + "cs4Label=httpStatusCode "
            + "cs4=200 "
            + "src=127.0.0.1 "
            + "dst=host.example.com"
    );
  }

  @Test
  public void log_recordsAnOperationAuditRecordToTheSysLogWhenUsingMTLS() {
    RequestAuditRecord requestAuditRecord = makeOperationAuditRecord("foo=bar", AUTH_METHOD_MUTUAL_TLS);

    subject.log(new SecurityEventAuditRecord(requestAuditRecord, "actor-id"));

    verify(securityEventsLogger).info(
        "CEF:0|cloud_foundry|credhub|"
            + fakeVersion
            + "|GET /api/some-path|"
            + "GET /api/some-path|0|rt="
            + String.valueOf(now.toEpochMilli())
            + " suser=user-name "
            + "suid=actor-id "
            + "cs1Label=userAuthenticationMechanism "
            + "cs1=mutual-tls "
            + "request=/api/some-path?foo=bar "
            + "requestMethod=GET "
            + "cs3Label=result "
            + "cs3=success "
            + "cs4Label=httpStatusCode "
            + "cs4=200 "
            + "src=127.0.0.1 "
            + "dst=host.example.com"
    );
  }

  @Test
  public void log_whenTheQueryParamStringIsNull_shouldSpecifyOnlyThePathInTheRequest() {
    RequestAuditRecord requestAuditRecord = makeOperationAuditRecord(
        null,
        AUTH_METHOD_UAA
    );
    subject.log(new SecurityEventAuditRecord(requestAuditRecord, "actor-id"));

    assertThat(fakeVersion, notNullValue());
    assertThat(fakeVersion.length(), greaterThan(0));

    verify(securityEventsLogger).info(contains("request=/api/some-path requestMethod=GET"));
  }

  @Test
  public void log_whenTheQueryParamStringIsEmpty_shouldSpecifyOnlyThePathInTheRequest() {
    RequestAuditRecord requestAuditRecord = makeOperationAuditRecord("", AUTH_METHOD_UAA);
    subject.log(new SecurityEventAuditRecord(requestAuditRecord, "actor-id"));

    assertThat(fakeVersion, notNullValue());
    assertThat(fakeVersion.length(), greaterThan(0));

    verify(securityEventsLogger).info(contains("request=/api/some-path requestMethod=GET"));
  }

  private RequestAuditRecord makeOperationAuditRecord(String queryParameters, String authMethod) {
    RequestAuditRecord requestAuditRecord = mock(RequestAuditRecord.class);
    when(requestAuditRecord.getAuthMethod()).thenReturn(authMethod);
    when(requestAuditRecord.getUserId()).thenReturn("user-id");
    when(requestAuditRecord.getNow()).thenReturn(now);
    when(requestAuditRecord.getMethod()).thenReturn("GET");
    when(requestAuditRecord.getPath()).thenReturn("/api/some-path");
    when(requestAuditRecord.getRequesterIp()).thenReturn("127.0.0.1");
    when(requestAuditRecord.getHostName()).thenReturn("host.example.com");
    when(requestAuditRecord.getClientId()).thenReturn("some-client-id");
    when(requestAuditRecord.getUserName()).thenReturn("user-name");
    when(requestAuditRecord.getQueryParameters()).thenReturn(queryParameters);
    when(requestAuditRecord.getStatusCode()).thenReturn(200);
    return requestAuditRecord;
  }
}
