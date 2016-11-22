package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.AuthFailureAuditRecord;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static com.greghaskins.spectrum.Spectrum.afterEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class AuthFailureAuditRecordDataServiceTest {
  @Autowired
  AuthFailureAuditRecordDataService subject;

  @Autowired
  JdbcTemplate jdbcTemplate;

  private final Instant frozenTime = Instant.ofEpochMilli(1400000000123L);
  private final long tokenIssued = frozenTime.toEpochMilli();
  private final long tokenExpires = tokenIssued + 10000;

  {
    wireAndUnwire(this, false);

    afterEach(() -> {
      jdbcTemplate.execute("delete from auth_failure_audit_record");
    });

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        AuthFailureAuditRecord record = createAuthFailureAuditRecord();
        record = subject.save(record);

        assertNotNull(record);

        List<AuthFailureAuditRecord> records = jdbcTemplate.query("select * from auth_failure_audit_record", (rs, rowCount) -> {
          AuthFailureAuditRecord r = new AuthFailureAuditRecord();
          r.setId(rs.getLong("id"));
          r.setFailureDescription(rs.getString("failure_description"));
          r.setHostName(rs.getString("host_name"));
          r.setNow(Instant.ofEpochMilli(rs.getLong("now")));
          r.setOperation(rs.getString("operation"));
          r.setPath(rs.getString("path"));
          r.setRequesterIp(rs.getString("requester_ip"));
          r.setTokenExpires(rs.getLong("token_expires"));
          r.setTokenIssued(rs.getLong("token_issued"));
          r.setUaaUrl(rs.getString("uaa_url"));
          r.setUserId(rs.getString("user_id"));
          r.setUserName(rs.getString("user_name"));
          r.setXForwardedFor(rs.getString("x_forwarded_for"));
          r.setScope(rs.getString("scope"));
          r.setGrantType(rs.getString("grant_type"));
          r.setClientId(rs.getString("client_id"));
          r.setMethod(rs.getString("method"));
          r.setStatusCode(rs.getInt("status_code"));
          r.setQueryParameters(rs.getString("query_parameters"));
          return r;
        });

        assertThat(records.size(), equalTo(1));

        AuthFailureAuditRecord expected = records.get(0);
        AuthFailureAuditRecord actual = record;

        assertThat(expected.getId(), equalTo(actual.getId()));
        assertThat(expected.getFailureDescription(), equalTo(actual.getFailureDescription()));
        assertThat(expected.getHostName(), equalTo(actual.getHostName()));
        assertThat(expected.getNow(), equalTo(actual.getNow()));
        assertThat(expected.getNow(), equalTo(frozenTime));
        assertThat(expected.getOperation(), equalTo(actual.getOperation()));
        assertThat(expected.getPath(), equalTo(actual.getPath()));
        assertThat(expected.getRequesterIp(), equalTo(actual.getRequesterIp()));
        assertThat(expected.getTokenExpires(), equalTo(actual.getTokenExpires()));
        assertThat(expected.getTokenExpires(), equalTo(tokenExpires));
        assertThat(expected.getTokenIssued(), equalTo(actual.getTokenIssued()));
        assertThat(expected.getTokenIssued(), equalTo(tokenIssued));
        assertThat(expected.getUaaUrl(), equalTo(actual.getUaaUrl()));
        assertThat(expected.getUserId(), equalTo(actual.getUserId()));
        assertThat(expected.getUserName(), equalTo(actual.getUserName()));
        assertThat(expected.getXForwardedFor(), equalTo(actual.getXForwardedFor()));
        assertThat(expected.getScope(), equalTo(actual.getScope()));
        assertThat(expected.getGrantType(), equalTo(actual.getGrantType()));
        assertThat(expected.getClientId(), equalTo(actual.getClientId()));
        assertThat(expected.getMethod(), equalTo(actual.getMethod()));
        assertThat(expected.getStatusCode(), equalTo(actual.getStatusCode()));
        assertThat(expected.getQueryParameters(), equalTo(actual.getQueryParameters()));
      });
    });
  }

  AuthFailureAuditRecord createAuthFailureAuditRecord() {
    AuthFailureAuditRecord record = new AuthFailureAuditRecord();
    record.setFailureDescription("it failed");
    record.setHostName("host.example.com");
    record.setNow(frozenTime);
    record.setOperation("test-operation");
    record.setPath("/api/some-path");
    record.setRequesterIp("127.0.0.1");
    record.setTokenExpires(tokenExpires);
    record.setTokenIssued(tokenIssued);
    record.setUaaUrl("https://uaa.example.com");
    record.setUserId("test-user-id");
    record.setUserName("test-user-name");
    record.setXForwardedFor("test-x-forwarded-for");
    record.setScope("test.scope");
    record.setGrantType("test-grant-type");
    record.setClientId("test-client-id");
    record.setMethod("GET");
    record.setStatusCode(500);
    record.setQueryParameters("query=param");

    return record;
  }
}
