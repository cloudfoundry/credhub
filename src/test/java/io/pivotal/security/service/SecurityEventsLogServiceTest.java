package io.pivotal.security.service;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_MUTUAL_TLS;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.mockito.Matchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.config.VersionProvider;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.util.CurrentTimeProvider;
import java.time.Instant;
import org.apache.logging.log4j.Logger;
import org.junit.runner.RunWith;
import org.springframework.security.core.context.SecurityContextHolder;

@RunWith(Spectrum.class)
public class SecurityEventsLogServiceTest {

  private final Instant now = Instant.now();
  private final String version = "FAKE-VERSION";

  private Logger securityEventsLogger;
  private CurrentTimeProvider currentTimeProvider;
  private VersionProvider versionProvider;
  private SecurityEventsLogService subject;

  {
    beforeEach(() -> {
      securityEventsLogger = mock(Logger.class);

      versionProvider = mock(VersionProvider.class);
      when(versionProvider.getVersion()).thenReturn(version);

      currentTimeProvider = mock(CurrentTimeProvider.class);
      when(currentTimeProvider.getInstant()).thenReturn(now);

      subject = new SecurityEventsLogService(securityEventsLogger, versionProvider);
    });

    afterEach(SecurityContextHolder::clearContext);

    describe("log", () -> {
      it("should log an operation audit record to the sys logwhen using oauth", () -> {
        RequestAuditRecord requestAuditRecord = makeOperationAuditRecord(
            "foo=bar",
            AUTH_METHOD_UAA);

        subject.log(requestAuditRecord);

        verify(securityEventsLogger).info(
            "CEF:0|cloud_foundry|credhub|"
                + version + "|GET /api/some-path|"
                + "GET /api/some-path|0|rt="
                + String.valueOf(now.toEpochMilli())
                + " suser=user-name "
                + "suid=user-id "
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
      });

      it("should log an operation audit record to the sys log when using mTLS", () -> {
        RequestAuditRecord requestAuditRecord = makeOperationAuditRecord("foo=bar",
            AUTH_METHOD_MUTUAL_TLS);

        subject.log(requestAuditRecord);

        verify(securityEventsLogger).info(
            "CEF:0|cloud_foundry|credhub|"
                + version
                + "|GET /api/some-path|"
                + "GET /api/some-path|0|rt="
                + String.valueOf(now.toEpochMilli())
                + " suser=user-name "
                + "suid=user-id "
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
      });

      describe("when the query param string is null", () -> {
        it("should specify only the path in the request", () -> {
          RequestAuditRecord requestAuditRecord = makeOperationAuditRecord(
              null,
              AUTH_METHOD_UAA
          );
          subject.log(requestAuditRecord);

          assertThat(version, notNullValue());
          assertThat(version.length(), greaterThan(0));

          verify(securityEventsLogger).info(contains("request=/api/some-path requestMethod=GET"));
        });
      });

      describe("when the query param string is an empty string", () -> {
        it("should specify only the path in the request", () -> {
          RequestAuditRecord requestAuditRecord = makeOperationAuditRecord("", AUTH_METHOD_UAA);
          subject.log(requestAuditRecord);

          assertThat(version, notNullValue());
          assertThat(version.length(), greaterThan(0));

          verify(securityEventsLogger).info(contains("request=/api/some-path requestMethod=GET"));
        });
      });
    });
  }

  private RequestAuditRecord makeOperationAuditRecord(String queryParameters, String authMethod) {
    return new RequestAuditRecord(
        authMethod,
        now,
        "some-path",
        "some_operation",
        "user-id",
        "user-name",
        "uaa.example.com",
        5000,
        6000,
        "host.example.com",
        "GET",
        "/api/some-path",
        queryParameters,
        200,
        "127.0.0.1",
        "1.2.3.4,5.6.7.8",
        "some-client-id",
        "credhub.read",
        "password",
        true
    );

  }
}
