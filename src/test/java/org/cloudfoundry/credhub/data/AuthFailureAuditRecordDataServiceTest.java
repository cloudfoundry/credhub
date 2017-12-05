package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.AuthFailureAuditRecord;
import org.cloudfoundry.credhub.repository.AuthFailureAuditRecordRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
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

import java.time.Instant;
import java.util.List;
import javax.persistence.EntityManager;

import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertNotNull;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class AuthFailureAuditRecordDataServiceTest {

  private final Instant frozenTime = Instant.ofEpochMilli(1400000000123L);
  private final long authValidFrom = frozenTime.toEpochMilli();
  private final long authValidUntil = authValidFrom + 10000;

  @Autowired
  JdbcTemplate jdbcTemplate;

  @Autowired
  EntityManager entityManager;

  @Autowired
  AuthFailureAuditRecordRepository authFailureAuditRecordRepository;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  AuthFailureAuditRecordDataService subject;
  private AuthFailureAuditRecord record;

  @Before
  public void beforeEach() {
    mockOutCurrentTimeProvider(currentTimeProvider).accept(frozenTime.toEpochMilli());

    subject = new AuthFailureAuditRecordDataService(authFailureAuditRecordRepository);

    record = createAuthFailureAuditRecord();
    record = subject.save(record);

    entityManager.flush();
  }

  @Test
  public void save_whenGivenARecord_savesTheRecord() {

    assertNotNull(record);

    List<AuthFailureAuditRecord> records = jdbcTemplate
        .query("select * from auth_failure_audit_record", (rs, rowCount) -> {
          AuthFailureAuditRecord r = new AuthFailureAuditRecord();
          r.setId(rs.getLong("id"));
          r.setFailureDescription(rs.getString("failure_description"));
          r.setHostName(rs.getString("host_name"));
          r.setNow(Instant.ofEpochMilli(rs.getLong("now")));
          r.setPath(rs.getString("path"));
          r.setRequesterIp(rs.getString("requester_ip"));
          r.setAuthValidUntil(rs.getLong("auth_valid_until"));
          r.setAuthValidFrom(rs.getLong("auth_valid_from"));
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
    assertThat(expected.getPath(), equalTo(actual.getPath()));
    assertThat(expected.getRequesterIp(), equalTo(actual.getRequesterIp()));
    assertThat(expected.getAuthValidUntil(), equalTo(actual.getAuthValidUntil()));
    assertThat(expected.getAuthValidUntil(), equalTo(authValidUntil));
    assertThat(expected.getAuthValidFrom(), equalTo(actual.getAuthValidFrom()));
    assertThat(expected.getAuthValidFrom(), equalTo(authValidFrom));
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
  }

  AuthFailureAuditRecord createAuthFailureAuditRecord() {
    AuthFailureAuditRecord record = new AuthFailureAuditRecord();
    record.setAuthMethod(UserContext.AUTH_METHOD_UAA);
    record.setFailureDescription("it failed");
    record.setHostName("host.example.com");
    record.setNow(frozenTime);
    record.setPath("/api/some-path");
    record.setRequesterIp("127.0.0.1");
    record.setAuthValidUntil(authValidUntil);
    record.setAuthValidFrom(authValidFrom);
    record.setUaaUrl("https://uaa.example.com");
    record.setUserId("test-user-id");
    record.setUserName("test-user-name");
    record.setXForwardedFor("test-x-forwarded-for");
    record.setScope("test.scope");
    record.setGrantType("test-grant-type");
    record.setClientId("test-client-id");
    record.setMethod("GET");
    record.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
    record.setQueryParameters("query=param");

    return record;
  }
}
