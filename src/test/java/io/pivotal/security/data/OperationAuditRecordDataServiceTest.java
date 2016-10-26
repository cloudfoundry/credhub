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
        assertThat(record, equalTo(records.get(0)));
      });
    });
  }

  OperationAuditRecord createOperationAuditRecord() {
    long year2000 = 946688461;
    Instant fakeNow = new Timestamp(year2000).toInstant();
    long tokenIssued = year2000;
    long tokenExpires = tokenIssued + 10000;
    int statusCode = 200;

    return new OperationAuditRecord(
        fakeNow,
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
