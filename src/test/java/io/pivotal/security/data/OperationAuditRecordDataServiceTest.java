package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.CredentialManagerTestContextBootstrapper;
import io.pivotal.security.entity.OperationAuditRecord;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.BootstrapWith;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static java.time.temporal.ChronoUnit.SECONDS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(Spectrum.class)
@SpringApplicationConfiguration(CredentialManagerApp.class)
@BootstrapWith(CredentialManagerTestContextBootstrapper.class)
@ActiveProfiles({"unit-test"})
public class OperationAuditRecordDataServiceTest {
  @Autowired
  OperationAuditRecordDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  private final Instant frozenTime = Instant.ofEpochSecond(1400000000L);
  private final long tokenIssued = frozenTime.getEpochSecond();
  private final long tokenExpires = tokenIssued + 10000;

  {
    wireAndUnwire(this);

    afterEach(() -> {
      jdbcTemplate.execute("delete from operation_audit_record");
    });

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        OperationAuditRecord record = createOperationAuditRecord();
        record = subject.save(record);

        assertNotNull(record);

        List<OperationAuditRecord> records = jdbcTemplate.query("select * from operation_audit_record", (rs, rowCount) -> {
          OperationAuditRecord r = new OperationAuditRecord(
              new Timestamp(rs.getLong("now")).toInstant(),
              rs.getString("operation"),
              rs.getString("user_id"),
              rs.getString("user_name"),
              rs.getString("uaa_url"),
              rs.getLong("token_issued"),
              rs.getLong("token_expires"),
              rs.getString("host_name"),
              rs.getString("method"),
              rs.getString("path"),
              rs.getString("query_parameters"),
              rs.getInt("status_code"),
              rs.getString("requester_ip"),
              rs.getString("x_forwarded_for"),
              rs.getString("client_id"),
              rs.getString("scope"),
              rs.getString("grant_type"),
              rs.getBoolean("success")
          );
          r.setId(rs.getLong("id"));
          return r;
        });

        assertThat(records.size(), equalTo(1));

        OperationAuditRecord actual = records.get(0);
        OperationAuditRecord expected = record;

        assertThat(actual.getId(), equalTo(expected.getId()));
        assertThat(actual.getNow(), equalTo(expected.getNow()));
        assertThat(actual.getNow(), equalTo(frozenTime));
        assertThat(actual.getOperation(), equalTo(expected.getOperation()));
        assertThat(actual.getUserId(), equalTo(expected.getUserId()));
        assertThat(actual.getUserName(), equalTo(expected.getUserName()));
        assertThat(actual.getUaaUrl(), equalTo(expected.getUaaUrl()));
        assertThat(actual.getTokenIssued(), equalTo(expected.getTokenIssued()));
        assertThat(actual.getTokenIssued(), equalTo(tokenIssued));
        assertThat(actual.getTokenExpires(), equalTo(expected.getTokenExpires()));
        assertThat(actual.getTokenExpires(), equalTo(tokenExpires));
        assertThat(actual.getHostName(), equalTo(expected.getHostName()));
        assertThat(actual.getMethod(), equalTo(expected.getMethod()));
        assertThat(actual.getPath(), equalTo(expected.getPath()));
        assertThat(actual.getQueryParameters(), equalTo(expected.getQueryParameters()));
        assertThat(actual.getStatusCode(), equalTo(expected.getStatusCode()));
        assertThat(actual.getRequesterIp(), equalTo(expected.getRequesterIp()));
        assertThat(actual.getXForwardedFor(), equalTo(expected.getXForwardedFor()));
        assertThat(actual.getClientId(), equalTo(expected.getClientId()));
        assertThat(actual.getScope(), equalTo(expected.getScope()));
        assertThat(actual.getGrantType(), equalTo(expected.getGrantType()));
        assertThat(actual.isSuccess(), equalTo(expected.isSuccess()));
      });
    });
  }

  OperationAuditRecord createOperationAuditRecord() {
    int statusCode = 200;

    return new OperationAuditRecord(
        frozenTime,
        "test-operation",
        "test-user-id",
        "test-user-name",
        "https://uaa.example.com",
        tokenIssued,
        tokenExpires,
        "host.example.com",
        "get",
        "/api/some-path",
        "query=param",
        statusCode,
        "127.0.0.1",
        "test-forwarded-for",
        "test-client-id",
        "test.scope",
        "test-grant-type",
        true
    );
  }
}
