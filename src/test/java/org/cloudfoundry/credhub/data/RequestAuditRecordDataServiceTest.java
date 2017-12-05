package org.cloudfoundry.credhub.data;

import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.UUID;
import javax.persistence.EntityManager;

import org.cloudfoundry.credhub.auth.UserContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class RequestAuditRecordDataServiceTest {

  private final Instant frozenTime = Instant.ofEpochSecond(1400000000L);
  private final long authValidFrom = frozenTime.getEpochSecond();
  private final long authValidUntil = authValidFrom + 10000;

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  EntityManager entityManager;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  RequestAuditRecordDataService subject;
  private RequestAuditRecord record;

  @Before
  public void beforeEach() {
    mockOutCurrentTimeProvider(currentTimeProvider).accept(frozenTime.toEpochMilli());

    subject = new RequestAuditRecordDataService(requestAuditRecordRepository);

    record = createOperationAuditRecord();
    record = subject.save(record);

    entityManager.flush();
  }

  @Test
  public void save_givenARecord_savesTheRecord() {

    assertNotNull(record);

    RequestAuditRecord actual = jdbcTemplate
        .queryForObject("select * from request_audit_record", (rs, rowNum) -> {
      return new RequestAuditRecord(
          getUuid(rs.getBytes("uuid")),
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
  }

  private UUID getUuid(byte[] uuid) {
    try {
      // For postgres
      return UUID.fromString(new String(uuid));
    } catch (IllegalArgumentException e) {
      // For H2 + mysql
      ByteBuffer byteBuffer = ByteBuffer.wrap(uuid);
      return new UUID(byteBuffer.getLong(), byteBuffer.getLong());
    }
  }

  RequestAuditRecord createOperationAuditRecord() {
    return new RequestAuditRecord(
        UUID.randomUUID(),
        Instant.now(),
        UserContext.AUTH_METHOD_UAA,
        "test-user-id",
        "test-user-name",
        "https://uaa.example.com",
        authValidFrom,
        authValidUntil,
        "host.example.com",
        "get",
        "/api/some-path",
        "query=param",
        HttpStatus.OK.value(),
        "127.0.0.1",
        "test-forwarded-for",
        "test-client-id",
        "test.scope",
        "test-grant-type"
    );
  }
}
