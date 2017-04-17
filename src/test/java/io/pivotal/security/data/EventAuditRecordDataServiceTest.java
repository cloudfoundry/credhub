package io.pivotal.security.data;

import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static org.hamcrest.CoreMatchers.isA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;

import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace = Replace.NONE)
public class EventAuditRecordDataServiceTest {
  private final Instant frozenTime = Instant.ofEpochSecond(1400000000L);

  @Autowired
  RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;

  @MockBean
  CurrentTimeProvider currentTimeProvider;

  private RequestAuditRecord requestAuditRecord;

  private EventAuditRecordDataService subject;

  @Before
  public void beforeEach() {
    mockOutCurrentTimeProvider(currentTimeProvider).accept(frozenTime.toEpochMilli());

    requestAuditRecord = requestAuditRecordRepository.save(new RequestAuditRecord(
        UUID.randomUUID(),
        frozenTime,
        "uaa",
        "test-user-id",
        "test-user-name",
        "http://uaa.example.com",
        1000L,
        2000L,
        "http://host.example.com",
        "GET",
        "/api/foo",
        "",
        HttpStatus.OK.value(),
        "127.0.0.1",
        "",
        "test-client-id",
        "test-scope",
        "password"
    ));

    subject = new EventAuditRecordDataService(eventAuditRecordRepository);
  }

  @Test
  public void save_givenARecord_savesTheRecord() {
    EventAuditRecord eventAuditRecord = new EventAuditRecord(
        "credential_access",
        "/test/credential",
        "test-actor",
        requestAuditRecord.getUuid(),
        true
    );
    subject.save(eventAuditRecord);

    List<EventAuditRecord> records = eventAuditRecordRepository.findAll();

    assertThat(records, hasSize(1));

    EventAuditRecord actual = records.get(0);

    assertThat(actual.getOperation(), equalTo("credential_access"));
    assertThat(actual.getCredentialName(), equalTo("/test/credential"));
    assertThat(actual.getActor(), equalTo("test-actor"));
    assertThat(actual.getRequestUuid(), equalTo(requestAuditRecord.getUuid()));
    assertThat(actual.isSuccess(), equalTo(true));
    assertThat(actual.getUuid(), isA(UUID.class));
    assertThat(actual.getNow(), equalTo(frozenTime));
  }
}
