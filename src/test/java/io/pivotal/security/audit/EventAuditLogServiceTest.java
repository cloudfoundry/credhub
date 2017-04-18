package io.pivotal.security.audit;

import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.SecretNameRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.TransactionStatus;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

import static com.google.common.collect.Lists.newArrayList;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static java.util.Collections.singletonList;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.data.domain.Sort.Direction.ASC;

@RunWith(SpringRunner.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
public class EventAuditLogServiceTest {
  @Autowired
  private EventAuditLogService subject;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @Autowired
  private SecretDataService secretDataService;

  @SpyBean
  private TransactionManagerDelegate transactionManager;

  @SpyBean
  private EventAuditRecordDataService eventAuditRecordDataService;

  @MockBean
  private CurrentTimeProvider currentTimeProvider;

  @Autowired
  private SecretNameRepository secretNameRepository;

  private final Instant now = Instant.ofEpochSecond(1490903353L);
  private final Instant then = Instant.ofEpochSecond(1550903353L);

  private UserContext userContext;
  private RequestUuid requestUuid;

  @Before
  public void beforeEach() {
    mockOutCurrentTimeProvider(currentTimeProvider).accept(now.toEpochMilli());
    userContext = mockUserContext(true);
    requestUuid = new RequestUuid(UUID.randomUUID());
  }

  // `@Transactional` for the tests messes with our rollback testing.
  @After
  public void afterEach() {
    secretNameRepository.deleteAllInBatch();
    eventAuditRecordRepository.deleteAllInBatch();
  }

  @Test
  public void auditEvent_whenTheEventAndAuditBothSucceed_auditsTheEvent() {
    subject.auditEvent(
        requestUuid,
        userContext,
        eventAuditRecordParameters -> {
          eventAuditRecordParameters.setCredentialName("keyName");
          eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_ACCESS);
          NamedValueSecretData entity = new NamedValueSecretData("keyName");
          entity.setEncryptedValue("value".getBytes());
          return secretDataService.save(entity);
        }
    );

    assertThat(secretDataService.count(), equalTo(1L));
    checkAuditRecord(true);
  }

  @Test(expected = AuditSaveFailureException.class)
  public void auditEvent_whenTheEventAndAuditBothFail_rollsBackAndThrowsAnException() {
    doThrow(new RuntimeException()).when(eventAuditRecordDataService)
        .save(any(List.class));

    userContext = mockUserContext(false);

    try {
      subject.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
        eventAuditRecordParameters.setCredentialName("keyName");

        NamedValueSecretData entity = new NamedValueSecretData("keyName");
        entity.setEncryptedValue("value".getBytes());
        secretDataService.save(entity);

        throw new RuntimeException("controller method failed");
      });
    } finally {
      final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
      verify(transactionManager, times(2)).rollback(captor.capture());

      List<TransactionStatus> transactionStatuses = captor.getAllValues();
      assertThat(transactionStatuses.get(0).isCompleted(), equalTo(true));
      assertThat(transactionStatuses.get(1).isCompleted(), equalTo(true));

      assertThat(secretDataService.count(), equalTo(0L));
      assertThat(eventAuditRecordRepository.count(), equalTo(0L));
    }
  }

  @Test(expected = AuditSaveFailureException.class)
  public void auditEvent_whenTheEventSucceeds_andTheAuditFails_rollsBackTheEventAndThrowsAnException() {
    doThrow(new RuntimeException()).when(eventAuditRecordDataService)
        .save(any(List.class));

    userContext = mockUserContext(false);

    try {
      subject.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
        eventAuditRecordParameters.setCredentialName("keyName");

        NamedValueSecretData entity = new NamedValueSecretData("keyName");
        entity.setEncryptedValue("value".getBytes());
        return secretDataService.save(entity);
      });
    } finally {
      final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
      verify(transactionManager, times(1)).rollback(captor.capture());

      List<TransactionStatus> transactionStatuses = captor.getAllValues();
      assertThat(transactionStatuses.get(0).isCompleted(), equalTo(true));

      assertThat(secretDataService.count(), equalTo(0L));
      assertThat(eventAuditRecordRepository.count(), equalTo(0L));
    }
  }

  @Test(expected = RuntimeException.class)
  public void auditEvent_whenTheEventFails_shouldAuditTheFailure() {
    try {
      subject.auditEvent(requestUuid, userContext, eventAuditRecordParameters -> {
        eventAuditRecordParameters.setCredentialName("keyName");
        eventAuditRecordParameters.setAuditingOperationCode(CREDENTIAL_ACCESS);

        NamedValueSecretData entity = new NamedValueSecretData("keyName");
        entity.setEncryptedValue("value".getBytes());
        secretDataService.save(entity);

        throw new RuntimeException("controller method failed");
      });
    } finally {
      checkAuditRecord(false);
    }
  }

  @Test
  public void auditEvents_whenTheEventAndAuditsBothSucceed_auditsTheEvent() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "foo"
    );

    subject.auditEvents(
        requestUuid,
        userContext,
        eventAuditRecordParametersList -> {
          eventAuditRecordParametersList.add(parameters1);
          eventAuditRecordParametersList.add(parameters2);

          NamedValueSecretData entity = new NamedValueSecretData("keyName");
          entity.setEncryptedValue("value".getBytes());
          return secretDataService.save(entity);
        }
    );

    assertThat(secretDataService.count(), equalTo(1L));
    checkAuditRecords(newArrayList(parameters1, parameters2), true);
  }

  @Test(expected = AuditSaveFailureException.class)
  public void auditEvents_whenTheEventAndAnAuditBothFail_rollsBackAndThrowsAnException() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "foo"
    );

    doThrow(new RuntimeException()).when(eventAuditRecordDataService)
        .save(any(List.class));

    userContext = mockUserContext(false);

    try {
      subject.auditEvents(requestUuid, userContext, eventAuditRecordParametersList -> {
        eventAuditRecordParametersList.add(parameters1);
        eventAuditRecordParametersList.add(parameters2);

        NamedValueSecretData entity = new NamedValueSecretData("keyName");
        entity.setEncryptedValue("value".getBytes());
        return secretDataService.save(entity);
      });
    } finally {
      final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
      verify(transactionManager, times(1)).rollback(captor.capture());

      List<TransactionStatus> transactionStatuses = captor.getAllValues();
      assertThat(transactionStatuses.get(0).isCompleted(), equalTo(true));

      assertThat(secretDataService.count(), equalTo(0L));
      assertThat(eventAuditRecordRepository.count(), equalTo(0L));
    }
  }

  @Test(expected = AuditSaveFailureException.class)
  public void auditEvents_whenTheEventSucceeds_andAnAuditFails_rollsBackTheEventAndThrowsAnException() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "foo"
    );

    doThrow(new RuntimeException()).when(eventAuditRecordDataService)
        .save(any(List.class));

    userContext = mockUserContext(false);

    try {
      subject.auditEvents(requestUuid, userContext, eventAuditRecordParametersList -> {
        eventAuditRecordParametersList.add(parameters1);
        eventAuditRecordParametersList.add(parameters2);

        NamedValueSecretData entity = new NamedValueSecretData("keyName");
        entity.setEncryptedValue("value".getBytes());

        secretDataService.save(entity);

        throw new RuntimeException("test");
      });
    } finally {
      final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
      verify(transactionManager, times(2)).rollback(captor.capture());

      List<TransactionStatus> transactionStatuses = captor.getAllValues();
      assertThat(transactionStatuses.get(1).isCompleted(), equalTo(true));

      assertThat(secretDataService.count(), equalTo(0L));
      assertThat(eventAuditRecordRepository.count(), equalTo(0L));
    }
  }

  @Test(expected = RuntimeException.class)
  public void auditEvents_whenTheEventFails_shouldAuditTheFailure() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "foo"
    );

    try {
      subject.auditEvents(requestUuid, userContext, eventAuditRecordParametersList -> {
        eventAuditRecordParametersList.add(parameters1);
        eventAuditRecordParametersList.add(parameters2);

        NamedValueSecretData entity = new NamedValueSecretData("keyName");
        entity.setEncryptedValue("value".getBytes());
        secretDataService.save(entity);

        throw new RuntimeException("controller method failed");
      });
    } finally {
      checkAuditRecords(newArrayList(parameters1, parameters2), false);
      assertThat(secretDataService.count(), equalTo(0L));
    }
  }

  private UserContext mockUserContext(boolean valid) {
    UserContext context = mock(UserContext.class);
    when(context.getValidFrom()).thenReturn(now.getEpochSecond());
    when(context.getValidUntil()).thenReturn(then.getEpochSecond());
    when(context.getClientId()).thenReturn("test-client-id");
    when(context.getAclUser()).thenReturn("test-actor");

    if (valid) {
      when(context.getAuthMethod()).thenReturn(AUTH_METHOD_UAA);
    }
    return context;
  }

  private void checkAuditRecord(boolean successFlag) {
    checkAuditRecords(singletonList(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "keyName")), successFlag);
  }

  private void checkAuditRecords(List<EventAuditRecordParameters> eventAuditRecordParameters, boolean successFlag) {
    final int expectedNumRecords = eventAuditRecordParameters.size();
    final List<EventAuditRecord> eventAuditRecords = eventAuditRecordRepository.findAll(new Sort(ASC, "credentialName"));
    assertThat(eventAuditRecords, hasSize(expectedNumRecords));

    eventAuditRecordParameters.sort(Comparator.comparing(EventAuditRecordParameters::getCredentialName));

    for (int i = 0; i < expectedNumRecords; i++) {
      final EventAuditRecordParameters parameters = eventAuditRecordParameters.get(i);
      final EventAuditRecord eventAuditRecord = eventAuditRecords.get(i);

      assertThat(eventAuditRecord.getCredentialName(), equalTo(parameters.getCredentialName()));
      assertThat(eventAuditRecord.getOperation(), equalTo(parameters.getAuditingOperationCode().toString()));
      assertThat(eventAuditRecord.getActor(), equalTo("test-actor"));
      assertThat(eventAuditRecord.isSuccess(), equalTo(successFlag));
      assertThat(eventAuditRecord.getRequestUuid(), equalTo(requestUuid.getUuid()));
      assertThat(eventAuditRecord.getRequestUuid(), notNullValue());
      assertThat(eventAuditRecord.getNow(), equalTo(this.now));
    }
  }
}
