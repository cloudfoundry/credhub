package io.pivotal.security.audit;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.entity.EventAuditRecord;
import org.hamcrest.Matchers;
import org.junit.runner.RunWith;

import java.util.UUID;

import static com.greghaskins.spectrum.Spectrum.it;
import static org.hamcrest.MatcherAssert.assertThat;

@RunWith(Spectrum.class)
public class EventAuditRecordBuilderTest {
  private final UUID requestUuid = UUID.randomUUID();

  {
    it("can create an audit record with a credential name", () -> {
      final EventAuditRecordBuilder subject = new EventAuditRecordBuilder(
          "test-actor"
      );
      subject.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);
      subject.setCredentialName("test-credential-name");

      final EventAuditRecord eventAuditRecord = subject.build(requestUuid, true);

      final EventAuditRecord expected = new EventAuditRecord(
          AuditingOperationCode.CREDENTIAL_ACCESS.toString(),
          "test-credential-name",
          "test-actor",
          requestUuid,
          true
      );

      assertThat(eventAuditRecord, Matchers.samePropertyValuesAs(expected));
    });

    it("can create an audit record without a credential name", () -> {
      final EventAuditRecordBuilder subject = new EventAuditRecordBuilder(
          "test-actor"
      );
      subject.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);

      final EventAuditRecord eventAuditRecord = subject.build(requestUuid, true);

      final EventAuditRecord expected = new EventAuditRecord(
          AuditingOperationCode.CREDENTIAL_ACCESS.toString(),
          null,
          "test-actor",
          requestUuid,
          true
      );

      assertThat(eventAuditRecord, Matchers.samePropertyValuesAs(expected));
    });

    it("can create an audit record without an operation", () -> {
      final UUID requestUuid = UUID.randomUUID();

      final EventAuditRecordBuilder subject = new EventAuditRecordBuilder(
          "test-actor"
      );

      final EventAuditRecord eventAuditRecord = subject.build(requestUuid, true);

      final EventAuditRecord expected = new EventAuditRecord(
          null,
          null,
          "test-actor",
          requestUuid,
          true
      );

      assertThat(eventAuditRecord, Matchers.samePropertyValuesAs(expected));
    });
  }
}
