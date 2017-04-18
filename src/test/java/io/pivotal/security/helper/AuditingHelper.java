package io.pivotal.security.helper;

import io.pivotal.security.audit.AuditingOperationCode;
import io.pivotal.security.audit.EventAuditRecordParameters;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import org.apache.commons.lang3.StringUtils;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.data.domain.Sort.Direction.DESC;

public class AuditingHelper {
  public static void verifyAuditing(
      RequestAuditRecordRepository requestAuditRecordRepository,
      EventAuditRecordRepository eventAuditRecordRepository,
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      String path,
      int statusCode
  ) {
    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(requestAuditRecord.getPath(), equalTo(path));
    assertThat(requestAuditRecord.getStatusCode(), equalTo(statusCode));

    EventAuditRecord eventAuditRecord = eventAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(eventAuditRecord.getOperation(), equalTo(auditingOperationCode.toString()));
    assertThat(eventAuditRecord.getCredentialName(), equalTo(credentialName));
    assertThat(eventAuditRecord.isSuccess(), equalTo(HttpStatus.valueOf(statusCode).is2xxSuccessful()));
  }

  public static void verifyAuditing(
      RequestAuditRecordRepository requestAuditRecordRepository,
      EventAuditRecordRepository eventAuditRecordRepository,
      String path,
      int statusCode,
      List<EventAuditRecordParameters> eventAuditRecordParametersList
  ) {
    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(requestAuditRecord.getPath(), equalTo(path));
    assertThat(requestAuditRecord.getStatusCode(), equalTo(statusCode));

    List<EventAuditRecord> eventAuditRecords = eventAuditRecordRepository.findAll(new Sort(DESC, "now"));
    assertThat(eventAuditRecords, hasSize(greaterThanOrEqualTo(eventAuditRecordParametersList.size())));

    boolean expectedSuccess = HttpStatus.valueOf(statusCode).is2xxSuccessful();

    assertThat(eventAuditRecords.subList(0, eventAuditRecordParametersList.size()),
        containsInAnyOrder(
          eventAuditRecordParametersList.stream()
              .map(parameters -> matchesExpectedEvent(parameters, expectedSuccess))
              .collect(Collectors.toList())
    ));
  }

  public static void verifyRequestAuditing(RequestAuditRecordRepository requestAuditRecordRepository, String path, int statusCode) {
    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(requestAuditRecord.getPath(), equalTo(path));
    assertThat(requestAuditRecord.getStatusCode(), equalTo(statusCode));
  }

  private static Matcher<EventAuditRecord> matchesExpectedEvent(EventAuditRecordParameters parameters, boolean expectedSuccess) {
    return new BaseMatcher<EventAuditRecord>() {
      @Override
      public boolean matches(Object item) {
        final EventAuditRecord actual = (EventAuditRecord) item;

        final String expectedAceOperation = parameters.getAceOperation() == null ? null : parameters.getAceOperation().getOperation();
        return StringUtils.equals(actual.getOperation(), parameters.getAuditingOperationCode().toString()) &&
            StringUtils.equals(actual.getCredentialName(), parameters.getCredentialName()) &&
            StringUtils.equals(actual.getAceOperation(), expectedAceOperation) &&
            StringUtils.equals(actual.getAceActor(), parameters.getAceActor()) &&
            actual.isSuccess() == expectedSuccess;
      }

      @Override
      public void describeTo(Description description) {
        description.appendText("Expected audit parameters did not match actual audit parameters");
      }
    };
  }
}
