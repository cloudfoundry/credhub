package io.pivotal.security.audit;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.EventAuditRecordDataService;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.util.CurrentTimeProvider;
import io.pivotal.security.util.DatabaseProfileResolver;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.TransactionStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
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
import static org.springframework.data.domain.Sort.Direction.DESC;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@SuppressWarnings("EmptyCatchBlock")
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

  private final Instant now = Instant.ofEpochSecond(1490903353L);
  private final Instant then = Instant.ofEpochSecond(1550903353L);

  private ResponseEntity<?> responseEntity;
  private UserContext userContext;

  private RequestUuid requestUuid;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockOutCurrentTimeProvider(currentTimeProvider).accept(now.toEpochMilli());
      userContext = mockUserContext(true);
      requestUuid = new RequestUuid(UUID.randomUUID());
    });

    describe("logging behavior", () -> {
      describe("when the action succeeds", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing(
                requestUuid,
                userContext,
                this::auditedSaveAndReturnNewValue
            );
          });

          it("performs the action", () -> {
            assertThat(secretDataService.count(), equalTo(1L));
          });

          it("passes the request untouched", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.OK));
          });

          it("logs the audit entries", () -> {
            checkAuditRecords(true);
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("does not perform the action", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            doThrow(new RuntimeException()).when(eventAuditRecordDataService)
                .save(any(EventAuditRecord.class));

            userContext = mockUserContext(false);

            try {
              responseEntity = subject.performWithAuditing(requestUuid, userContext, auditRecordBuilder -> {
                return auditedSaveAndReturnNewValue(auditRecordBuilder);
              });
            } finally {
              assertThat(secretDataService.count(), equalTo(0L));
            }
          });
        });
      });

      describe("when the action fails with an exception", () -> {
        describe("when the audit succeeds", () -> {
          AtomicReference<Exception> exception = new AtomicReference<>();
          RuntimeException re = new RuntimeException("controller method failed");

          beforeEach(() -> {
            exception.set(null);
            try {
              subject.performWithAuditing(requestUuid, userContext, auditRecordBuilder -> {
                auditRecordBuilder.setCredentialName("keyName");
                auditRecordBuilder.setAuditingOperationCode(CREDENTIAL_ACCESS);

                NamedValueSecretData entity = new NamedValueSecretData("keyName");
                entity.setEncryptedValue("value".getBytes());
                secretDataService.save(entity);
                throw re;
              });
            } catch (Exception e) {
              exception.set(e);
            }
          });

          it("leaves the 500 response from the controller alone", () -> {
            assertThat(exception.get(), equalTo(re));
          });

          it("logs failed audit entry", () -> {
            checkAuditRecords(false);
            assertThat(secretDataService.count(), equalTo(0L));
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("rolls back commit", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            doThrow(new RuntimeException()).when(eventAuditRecordDataService)
                .save(any(EventAuditRecord.class));

            userContext = mockUserContext(false);

            try {
              responseEntity = subject.performWithAuditing(requestUuid, userContext, auditRecordBuilder -> {
                auditRecordBuilder.setCredentialName("keyName");

                NamedValueSecretData entity = new NamedValueSecretData("keyName");
                entity.setEncryptedValue("value".getBytes());
                secretDataService.save(entity);

                throw new RuntimeException("controller method failed");
              });
            } finally {
              final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
              verify(transactionManager, times(2)).rollback(captor.capture());

              List<TransactionStatus> transactionStatuses = captor.getAllValues();
              assertThat(transactionStatuses.get(1).isCompleted(), equalTo(true));

              assertThat(secretDataService.count(), equalTo(0L));
            }
          });
        });
      });
    });
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

  private ResponseEntity<?> auditedSaveAndReturnNewValue(EventAuditRecordBuilder auditRecordBuilder) {
    auditRecordBuilder.setCredentialName("keyName");
    auditRecordBuilder.setAuditingOperationCode(CREDENTIAL_ACCESS);
    NamedValueSecretData entity = new NamedValueSecretData("keyName");
    entity.setEncryptedValue("value".getBytes());
    final NamedValueSecret secret = secretDataService.save(entity);
    return new ResponseEntity<>(secret, HttpStatus.OK);
  }

  private void checkAuditRecords(boolean successFlag) {
    final List<EventAuditRecord> eventAuditRecords = eventAuditRecordRepository.findAll(new Sort(DESC, "now"));

    assertThat(eventAuditRecords, hasSize(1));

    EventAuditRecord eventAuditRecord = eventAuditRecords.get(0);
    assertThat(eventAuditRecord.getCredentialName(), equalTo("keyName"));
    assertThat(eventAuditRecord.getActor(), equalTo("test-actor"));
    assertThat(eventAuditRecord.isSuccess(), equalTo(successFlag));
    assertThat(eventAuditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
    assertThat(eventAuditRecord.getRequestUuid(), equalTo(requestUuid.getUuid()));
    assertThat(eventAuditRecord.getRequestUuid(), notNullValue());
    assertThat(eventAuditRecord.getNow(), equalTo(this.now));
  }
}
