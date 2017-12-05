package org.cloudfoundry.credhub.data;

import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
import static org.hamcrest.CoreMatchers.isA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.data.domain.Sort.Direction.ASC;

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
  public void saveAll_givenAListOfRecords_savesTheRecords() {
    EventAuditRecord eventAuditRecord1 = new EventAuditRecord(
        "credential_access",
        "/test/credential1",
        "test-actor1",
        requestAuditRecord.getUuid(),
        true,
        null, null
    );
    EventAuditRecord eventAuditRecord2 = new EventAuditRecord(
        "credential_update",
        "/test/credential2",
        "test-actor2",
        requestAuditRecord.getUuid(),
        false,
        "credential_access", "ace-actor"
    );
    subject.save(newArrayList(eventAuditRecord1, eventAuditRecord2));

    List<EventAuditRecord> records = eventAuditRecordRepository.findAll(new Sort(ASC, "credentialName"));

    assertThat(records, hasSize(2));

    EventAuditRecord actual1 = records.get(0);
    assertThat(actual1.getOperation(), equalTo("credential_access"));
    assertThat(actual1.getCredentialName(), equalTo("/test/credential1"));
    assertThat(actual1.getActor(), equalTo("test-actor1"));
    assertThat(actual1.getRequestUuid(), equalTo(requestAuditRecord.getUuid()));
    assertThat(actual1.isSuccess(), equalTo(true));
    assertThat(actual1.getUuid(), isA(UUID.class));
    assertThat(actual1.getNow(), equalTo(frozenTime));
    assertThat(actual1.getAceActor(), equalTo(null));
    assertThat(actual1.getAceOperation(), equalTo(null));

    EventAuditRecord actual2 = records.get(1);
    assertThat(actual2.getOperation(), equalTo("credential_update"));
    assertThat(actual2.getCredentialName(), equalTo("/test/credential2"));
    assertThat(actual2.getActor(), equalTo("test-actor2"));
    assertThat(actual2.getRequestUuid(), equalTo(requestAuditRecord.getUuid()));
    assertThat(actual2.isSuccess(), equalTo(false));
    assertThat(actual2.getUuid(), isA(UUID.class));
    assertThat(actual2.getNow(), equalTo(frozenTime));
    assertThat(actual2.getAceActor(), equalTo("ace-actor"));
    assertThat(actual2.getAceOperation(), equalTo("credential_access"));
  }
}
