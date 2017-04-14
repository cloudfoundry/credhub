package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static java.util.UUID.nameUUIDFromBytes;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class RequestAuditRecordDataServiceTest {

  private final Instant frozenTime = Instant.ofEpochSecond(1400000000L);
  private final long authValidFrom = frozenTime.getEpochSecond();
  private final long authValidUntil = authValidFrom + 10000;
  @Autowired
  RequestAuditRecordDataService subject;
  @Autowired
  JdbcTemplate jdbcTemplate;
  @MockBean
  CurrentTimeProvider currentTimeProvider;
  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockOutCurrentTimeProvider(currentTimeProvider).accept(frozenTime.toEpochMilli());
    });

    describe("#save", () -> {
      it("should create the entity in the database", () -> {
        RequestAuditRecord record = createOperationAuditRecord();
        record = subject.save(record);

        assertNotNull(record);

        RequestAuditRecord actual = jdbcTemplate.queryForObject("select * from request_audit_record", (rs, rowNum) -> {
          ByteBuffer uuidBytes = ByteBuffer.wrap(rs.getBytes("uuid"));
          UUID uuid = new UUID(uuidBytes.getLong(), uuidBytes.getLong());

          return new RequestAuditRecord(
              uuid,
              Instant.ofEpochMilli(rs.getLong("now")),
              rs.getString("auth_method"),
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
              rs.getString("grant_type"));
        });

        assertThat(actual.getUuid(), equalTo(record.getUuid()));
        assertThat(actual.getNow(), equalTo(record.getNow()));
        assertThat(actual.getAuthMethod(), equalTo(record.getAuthMethod()));
        assertThat(actual.getUserId(), equalTo(record.getUserId()));
        assertThat(actual.getUserName(), equalTo(record.getUserName()));
        assertThat(actual.getUaaUrl(), equalTo(record.getUaaUrl()));
        assertThat(actual.getAuthValidFrom(), equalTo(record.getAuthValidFrom()));
        assertThat(actual.getAuthValidFrom(), equalTo(authValidFrom));
        assertThat(actual.getAuthValidUntil(), equalTo(record.getAuthValidUntil()));
        assertThat(actual.getAuthValidUntil(), equalTo(authValidUntil));
        assertThat(actual.getHostName(), equalTo(record.getHostName()));
        assertThat(actual.getMethod(), equalTo(record.getMethod()));
        assertThat(actual.getPath(), equalTo(record.getPath()));
        assertThat(actual.getQueryParameters(), equalTo(record.getQueryParameters()));
        assertThat(actual.getStatusCode(), equalTo(record.getStatusCode()));
        assertThat(actual.getRequesterIp(), equalTo(record.getRequesterIp()));
        assertThat(actual.getXForwardedFor(), equalTo(record.getXForwardedFor()));
        assertThat(actual.getClientId(), equalTo(record.getClientId()));
        assertThat(actual.getScope(), equalTo(record.getScope()));
        assertThat(actual.getGrantType(), equalTo(record.getGrantType()));
      });
    });
  }

  RequestAuditRecord createOperationAuditRecord() {
    int statusCode = 200;

    return new RequestAuditRecord(
        UUID.randomUUID(),
        Instant.now(),
        AUTH_METHOD_UAA,
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
        "test-grant-type");
  }
}
