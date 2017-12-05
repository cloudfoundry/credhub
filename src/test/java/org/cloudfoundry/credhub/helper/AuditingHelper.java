package org.cloudfoundry.credhub.helper;

import org.cloudfoundry.credhub.audit.AuditingOperationCode;
import org.cloudfoundry.credhub.audit.EventAuditRecordParameters;
import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.repository.RequestAuditRecordRepository;
import org.apache.commons.lang3.StringUtils;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.springframework.data.domain.Sort.Direction.DESC;

public class AuditingHelper {

  private final RequestAuditRecordRepository requestAuditRecordRepository;
  private final EventAuditRecordRepository eventAuditRecordRepository;

  public AuditingHelper(RequestAuditRecordRepository requestAuditRecordRepository,
      EventAuditRecordRepository eventAuditRecordRepository) {

    this.requestAuditRecordRepository = requestAuditRecordRepository;
    this.eventAuditRecordRepository = eventAuditRecordRepository;
  }

  public void verifyAuditing(
      AuditingOperationCode auditingOperationCode,
      String credentialName,
      String actor,
      String path,
      int statusCode
  ) {
    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(requestAuditRecord.getPath(), equalTo(path));
    assertThat(requestAuditRecord.getStatusCode(), equalTo(statusCode));

    List<EventAuditRecord> auditRecords = eventAuditRecordRepository.findAll(new Sort(DESC, "now"));
    EventAuditRecord eventAuditRecord = auditRecords.get(0);
    assertThat(eventAuditRecord.getOperation(), equalTo(auditingOperationCode.toString()));
    assertThat(eventAuditRecord.getCredentialName(), equalTo(credentialName));
    assertThat(eventAuditRecord.isSuccess(), equalTo(HttpStatus.valueOf(statusCode).is2xxSuccessful()));
    assertThat(eventAuditRecord.getActor(), equalTo(actor));

    assertThat(requestAuditRecord.getUuid(), equalTo(eventAuditRecord.getRequestUuid()));
  }

  public void verifyAuditing(
      String actor,
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
              .map(parameters -> matchesExpectedEvent(parameters, actor, expectedSuccess, requestAuditRecord.getUuid()))
              .collect(Collectors.toList())
    ));
  }

  public void verifyRequestAuditing(String path, int statusCode) {
    RequestAuditRecord requestAuditRecord = requestAuditRecordRepository.findAll(new Sort(DESC, "now")).get(0);
    assertThat(requestAuditRecord.getPath(), equalTo(path));
    assertThat(requestAuditRecord.getStatusCode(), equalTo(statusCode));
  }

  private static Matcher<EventAuditRecord> matchesExpectedEvent(EventAuditRecordParameters parameters, String actor, boolean expectedSuccess, UUID requestUuid ) {
    return new BaseMatcher<EventAuditRecord>() {
      @Override
      public boolean matches(Object item) {
        final EventAuditRecord actual = (EventAuditRecord) item;

        final String expectedAceOperation = parameters.getAceOperation() == null ? null : parameters.getAceOperation().getOperation();
        return StringUtils.equals(actual.getOperation(), parameters.getAuditingOperationCode().toString()) &&
            StringUtils.equals(actual.getCredentialName(), parameters.getCredentialName()) &&
            StringUtils.equals(actual.getAceOperation(), expectedAceOperation) &&
            StringUtils.equals(actual.getAceActor(), parameters.getAceActor()) &&
            StringUtils.equals(actual.getActor(), actor) &&
            actual.isSuccess() == expectedSuccess &&
            actual.getRequestUuid().equals(requestUuid);
      }

      @Override
      public void describeTo(Description message) {
        message.appendText("Expected audit parameters did not match actual audit parameters: ");
      }
    };
  }
}
