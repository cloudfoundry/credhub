package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class OperationAuditRecordDataServiceTest {
  @Autowired
  OperationAuditRecordDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  private final Instant frozenTime = Instant.ofEpochSecond(1400000000L);
  private final long authValidFrom = frozenTime.getEpochSecond();
  private final long authValidUntil = authValidFrom + 10000;

  {
    wireAndUnwire(this);

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        OperationAuditRecord record = createOperationAuditRecord();
        record = subject.save(record);

        assertNotNull(record);

        List<OperationAuditRecord> records = jdbcTemplate.query("select * from operation_audit_record", (rs, rowCount) -> {
          OperationAuditRecord r = new OperationAuditRecord(
              rs.getString("auth_method"),
              new Timestamp(rs.getLong("now")).toInstant(),
              rs.getString("credential_name"),
              rs.getString("operation"),
              rs.getString("user_id"),
              rs.getString("user_name"),
              rs.getString("uaa_url"),
              rs.getLong("auth_valid_from"),
              rs.getLong("auth_valid_until"),
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
        assertThat(actual.getAuthMethod(), equalTo(expected.getAuthMethod()));
        assertThat(actual.getNow(), equalTo(expected.getNow()));
        assertThat(actual.getNow(), equalTo(frozenTime));
        assertThat(actual.getOperation(), equalTo(expected.getOperation()));
        assertThat(actual.getCredentialName(), equalTo(expected.getCredentialName()));
        assertThat(actual.getUserId(), equalTo(expected.getUserId()));
        assertThat(actual.getUserName(), equalTo(expected.getUserName()));
        assertThat(actual.getUaaUrl(), equalTo(expected.getUaaUrl()));
        assertThat(actual.getAuthValidFrom(), equalTo(expected.getAuthValidFrom()));
        assertThat(actual.getAuthValidFrom(), equalTo(authValidFrom));
        assertThat(actual.getAuthValidUntil(), equalTo(expected.getAuthValidUntil()));
        assertThat(actual.getAuthValidUntil(), equalTo(authValidUntil));
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
        "uaa",
        frozenTime,
        "fake-credential-name",
        "test-operation",
        "test-user-id",
        "test-user-name",
        "https://uaa.example.com",
        authValidFrom,
        authValidUntil,
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
