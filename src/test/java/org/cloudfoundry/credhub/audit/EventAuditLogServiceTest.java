package org.cloudfoundry.credhub.audit;

import org.cloudfoundry.credhub.CredentialManagerApp;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.data.CredentialVersionDataService;
import org.cloudfoundry.credhub.data.EventAuditRecordDataService;
import org.cloudfoundry.credhub.entity.EncryptedValue;
import org.cloudfoundry.credhub.entity.EncryptionKeyCanary;
import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.cloudfoundry.credhub.entity.ValueCredentialVersionData;
import org.cloudfoundry.credhub.exceptions.AuditSaveFailureException;
import org.cloudfoundry.credhub.repository.EncryptionKeyCanaryRepository;
import org.cloudfoundry.credhub.repository.EventAuditRecordRepository;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.cloudfoundry.credhub.util.DatabaseProfileResolver;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
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

import static com.google.common.collect.Lists.newArrayList;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static org.cloudfoundry.credhub.audit.AuditingOperationCode.CREDENTIAL_UPDATE;
import static org.cloudfoundry.credhub.helper.TestHelper.mockOutCurrentTimeProvider;
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
  private UserContextHolder userContextHolder;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @Autowired
  private CredentialVersionDataService credentialVersionDataService;

  @SpyBean
  private TransactionManagerDelegate transactionManager;

  @SpyBean
  private EventAuditRecordDataService eventAuditRecordDataService;

  @MockBean
  private CurrentTimeProvider currentTimeProvider;

  @Autowired
  private Flyway flyway;

  @Autowired
  private EncryptionKeyCanaryRepository encryptionKeyCanaryRepository;

  @Autowired
  private RequestUuid requestUuid;

  private final Instant now = Instant.ofEpochSecond(1490903353L);
  private final Instant then = Instant.ofEpochSecond(1550903353L);

  private UserContext userContext;
  private List<EncryptionKeyCanary> canaries;
  private ValueCredentialVersionData entity;

  @Before
  public void beforeEach() {
    canaries = encryptionKeyCanaryRepository.findAll();

    mockOutCurrentTimeProvider(currentTimeProvider).accept(now.toEpochMilli());
    userContext = mockUserContext(true);
    userContextHolder.setUserContext(userContext);

    entity = new ValueCredentialVersionData("keyName");
    entity.setEncryptedValueData(new EncryptedValue(
        canaries.get(0).getUuid(),
        "value",
        "nonce"));
  }

  @After
  public void afterEach() {
    flyway.clean();
    flyway.setTarget(MigrationVersion.LATEST);
    flyway.migrate();

    encryptionKeyCanaryRepository.save(canaries);
    encryptionKeyCanaryRepository.flush();
  }

  @Test
  public void auditEvents_whenTheEventAndAuditsBothSucceed_auditsTheEvent() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "/test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "/foo"
    );

    subject.auditEvents(
        eventAuditRecordParametersList -> {
          eventAuditRecordParametersList.add(parameters1);
          eventAuditRecordParametersList.add(parameters2);
          return credentialVersionDataService.save(entity);
        }
    );

    assertThat(credentialVersionDataService.count(), equalTo(1L));
    checkAuditRecords(newArrayList(parameters1, parameters2), true);
  }

  @Test(expected = AuditSaveFailureException.class)
  public void auditEvents_whenTheEventAndAnAuditBothFail_rollsBackAndThrowsAnException() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "/test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "/foo"
    );

    doThrow(new RuntimeException()).when(eventAuditRecordDataService)
        .save(any(List.class));

    userContext = mockUserContext(false);

    try {
      subject.auditEvents(eventAuditRecordParametersList -> {
        eventAuditRecordParametersList.add(parameters1);
        eventAuditRecordParametersList.add(parameters2);
        return credentialVersionDataService.save(entity);
      });
    } finally {
      final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
      verify(transactionManager, times(1)).rollback(captor.capture());

      List<TransactionStatus> transactionStatuses = captor.getAllValues();
      assertThat(transactionStatuses.get(0).isCompleted(), equalTo(true));

      assertThat(credentialVersionDataService.count(), equalTo(0L));
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
      subject.auditEvents(eventAuditRecordParametersList -> {
        eventAuditRecordParametersList.add(parameters1);
        eventAuditRecordParametersList.add(parameters2);
        credentialVersionDataService.save(entity);

        throw new RuntimeException("test");
      });
    } finally {
      final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
      verify(transactionManager, times(2)).rollback(captor.capture());

      List<TransactionStatus> transactionStatuses = captor.getAllValues();
      assertThat(transactionStatuses.get(1).isCompleted(), equalTo(true));

      assertThat(credentialVersionDataService.count(), equalTo(0L));
      assertThat(eventAuditRecordRepository.count(), equalTo(0L));
    }
  }

  @Test(expected = RuntimeException.class)
  public void auditEvents_whenTheEventFails_shouldAuditTheFailure() {
    EventAuditRecordParameters parameters1 = new EventAuditRecordParameters(
        CREDENTIAL_UPDATE,
        "/test-credential"
    );
    EventAuditRecordParameters parameters2 = new EventAuditRecordParameters(
        CREDENTIAL_ACCESS,
        "/foo"
    );

    try {
      subject.auditEvents(eventAuditRecordParametersList -> {
        eventAuditRecordParametersList.add(parameters1);
        eventAuditRecordParametersList.add(parameters2);
        credentialVersionDataService.save(entity);

        throw new RuntimeException("controller method failed");
      });
    } finally {
      checkAuditRecords(newArrayList(parameters1, parameters2), false);
      assertThat(credentialVersionDataService.count(), equalTo(0L));
    }
  }

  private UserContext mockUserContext(boolean valid) {
    UserContext context = mock(UserContext.class);
    when(context.getValidFrom()).thenReturn(now.getEpochSecond());
    when(context.getValidUntil()).thenReturn(then.getEpochSecond());
    when(context.getClientId()).thenReturn("test-client-id");
    when(context.getActor()).thenReturn("test-actor");

    if (valid) {
      when(context.getAuthMethod()).thenReturn(UserContext.AUTH_METHOD_UAA);
    }
    return context;
  }

  private void checkAuditRecord(boolean successFlag) {
    checkAuditRecords(singletonList(new EventAuditRecordParameters(CREDENTIAL_ACCESS, "/keyName")), successFlag);
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
