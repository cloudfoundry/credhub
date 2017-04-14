package io.pivotal.security.data;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static org.hamcrest.CoreMatchers.isA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsCollectionWithSize.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;

@RunWith(Spectrum.class)
@ActiveProfiles(value = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EventAuditRecordDataServiceTest {
  private final Instant frozenTime = Instant.ofEpochSecond(1400000000L);

  @Autowired
  private EventAuditRecordDataService subject;
  @Autowired
  RequestAuditRecordDataService requestAuditRecordDataService;
  @Autowired
  EventAuditRecordRepository eventAuditRecordRepository;
  @MockBean
  CurrentTimeProvider currentTimeProvider;
  private RequestAuditRecord requestAuditRecord;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockOutCurrentTimeProvider(currentTimeProvider).accept(frozenTime.toEpochMilli());

      requestAuditRecord = requestAuditRecordDataService.save(new RequestAuditRecord(
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
          200,
          "127.0.0.1",
          "",
          "test-client-id",
          "test-scope",
          "password"
      ));
    });

    describe("#save", () -> {
      it("should create the record in the database", () -> {
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
      });
    });
  }
}
