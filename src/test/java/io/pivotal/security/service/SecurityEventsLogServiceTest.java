package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.OperationAuditRecord;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.apache.logging.log4j.Logger;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import org.junit.runner.RunWith;
import static org.mockito.Matchers.contains;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class SecurityEventsLogServiceTest {
  @MockBean
  Logger securityEventsLoggerMock;

  @Autowired
  SecurityEventsLogService subject;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  @Value("${info.app.version}")
  String version;

  private Instant now;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      now = Instant.now();

      when(currentTimeProvider.getInstant()).thenReturn(now);
    });

    describe("log", () -> {
      it("should log an operation audit record to the sys log", () -> {
        OperationAuditRecord operationAuditRecord = new OperationAuditRecord(
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
            "foo=bar",
            200,
            "127.0.0.1",
            "1.2.3.4,5.6.7.8",
            "some-client-id",
            "credhub.read",
            "password",
            true
        );
        subject.log(operationAuditRecord);

        assertThat(version, notNullValue());
        assertThat(version.length(), greaterThan(0));

        verify(securityEventsLoggerMock).info(
            "CEF:0|cloud_foundry|credhub|" +
            version + "|" +
            "GET /api/some-path|" +
            "GET /api/some-path|0|rt=" +
            String.valueOf(now.toEpochMilli()) + " " +
            "suser=user-name " +
            "suid=user-id " +
            "cs1Label=userAuthenticationMechanism " +
            "cs1=oauth-access-token " +
            "request=/api/some-path?foo=bar " +
            "requestMethod=GET " +
            "cs3Label=result " +
            "cs3=success " +
            "cs4Label=httpStatusCode " +
            "cs4=200 " +
            "src=127.0.0.1 " +
            "dst=host.example.com"
        );
      });

      describe("when the query param string is null", () -> {
        it("should specify only the path in the request", () -> {
          OperationAuditRecord operationAuditRecord = new OperationAuditRecord(
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
              null,
              200,
              "127.0.0.1",
              "1.2.3.4,5.6.7.8",
              "some-client-id",
              "credhub.read",
              "password",
              true
          );
          subject.log(operationAuditRecord);

          assertThat(version, notNullValue());
          assertThat(version.length(), greaterThan(0));

          verify(securityEventsLoggerMock).info(contains("request=/api/some-path requestMethod=GET"));
        });
      });

      describe("when the query param string is an empty string", () -> {
        it("should specify only the path in the request", () -> {
          OperationAuditRecord operationAuditRecord = new OperationAuditRecord(
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
              "",
              200,
              "127.0.0.1",
              "1.2.3.4,5.6.7.8",
              "some-client-id",
              "credhub.read",
              "password",
              true
          );
          subject.log(operationAuditRecord);

          assertThat(version, notNullValue());
          assertThat(version.length(), greaterThan(0));

          verify(securityEventsLoggerMock).info(contains("request=/api/some-path requestMethod=GET"));
        });
      });
    });
  }
}
