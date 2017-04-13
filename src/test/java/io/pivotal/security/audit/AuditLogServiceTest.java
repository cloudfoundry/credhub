package io.pivotal.security.audit;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.CredentialManagerApp;
import io.pivotal.security.auth.UserContext;
import io.pivotal.security.data.SecretDataService;
import io.pivotal.security.domain.NamedValueSecret;
import io.pivotal.security.entity.EventAuditRecord;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.repository.EventAuditRecordRepository;
import io.pivotal.security.repository.RequestAuditRecordRepository;
import io.pivotal.security.service.SecurityEventsLogService;
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
import java.util.concurrent.atomic.AtomicReference;
import javax.servlet.http.HttpServletRequest;

import static com.google.common.collect.Lists.newArrayList;
import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.audit.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.auth.UserContext.AUTH_METHOD_UAA;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.helper.SpectrumHelper.mockOutCurrentTimeProvider;
import static io.pivotal.security.helper.SpectrumHelper.wireAndUnwire;
import static java.util.Collections.enumeration;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.data.domain.Sort.Direction.DESC;

@RunWith(Spectrum.class)
@ActiveProfiles(profiles = {"unit-test"}, resolver = DatabaseProfileResolver.class)
@SpringBootTest(classes = CredentialManagerApp.class)
@SuppressWarnings("EmptyCatchBlock")
public class AuditLogServiceTest {
  @Autowired
  private AuditLogService subject;

  @MockBean
  private SecurityEventsLogService securityEventsLogService;

  @Autowired
  private RequestAuditRecordRepository requestAuditRecordRepository;

  @Autowired
  private EventAuditRecordRepository eventAuditRecordRepository;

  @Autowired
  private SecretDataService secretDataService;

  @SpyBean
  private TransactionManagerDelegate transactionManager;

  @MockBean
  private CurrentTimeProvider currentTimeProvider;

  private final Instant now = Instant.ofEpochSecond(1490903353L);
  private final Instant then = Instant.ofEpochSecond(1550903353L);

  private ResponseEntity<?> responseEntity;
  private UserContext userContext;

  private HttpServletRequest request;

  {
    wireAndUnwire(this);

    beforeEach(() -> {
      mockOutCurrentTimeProvider(currentTimeProvider).accept(now.toEpochMilli());
      userContext = mockUserContext(true);
      request = mockRequest();
    });

    describe("logging behavior", () -> {
      describe("when the action succeeds", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing(
                request,
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
            checkAuditRecords(true, HttpStatus.OK);
          });

          it("logs in CEF format to file", () -> {
            verify(securityEventsLogService).log(isA(RequestAuditRecord.class));
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("does not perform the action or write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            userContext = mockUserContext(false);

            try {
              responseEntity = subject.performWithAuditing(request, userContext, auditRecordBuilder -> {
                return auditedSaveAndReturnNewValue(auditRecordBuilder);
              });
            } finally {
              assertThat(secretDataService.count(), equalTo(0L));
              verify(securityEventsLogService, times(0)).log(isA(RequestAuditRecord.class));
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
              subject.performWithAuditing(request, userContext, auditRecordBuilder -> {
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
            checkAuditRecords(false, HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(secretDataService.count(), equalTo(0L));
          });

          it("should write to the CEF log file", () -> {
            verify(securityEventsLogService).log(isA(RequestAuditRecord.class));
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("rolls back commit and doesn't write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            userContext = mockUserContext(false);

            try {
              responseEntity = subject.performWithAuditing(request, userContext, auditRecordBuilder -> {
                auditRecordBuilder.setCredentialName("keyName");

                NamedValueSecretData entity = new NamedValueSecretData("keyName");
                entity.setEncryptedValue("value".getBytes());
                secretDataService.save(entity);

                throw new RuntimeException("controller method failed");
              });
            } finally {
              System.out.print("hello");
              verify(securityEventsLogService, times(0)).log(isA(RequestAuditRecord.class));
              verify(transactionManager, times(1)).rollback(isA(TransactionStatus.class));
              assertThat(secretDataService.count(), equalTo(0L));

            }
          });
        });
      });

      describe("when the action fails with a non 200 status", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing(request, userContext, auditRecordBuilder -> {
              auditRecordBuilder.setAuditingOperationCode(AuditingOperationCode.CREDENTIAL_ACCESS);
              return auditedSaveNewValueWithBadGateway(auditRecordBuilder);
            });
          });

          it("logs audit entry for failure", () -> {
            checkAuditRecords(false, HttpStatus.BAD_GATEWAY);
            assertThat(secretDataService.count(), equalTo(0L));
          });

          it("returns the non-2xx status code", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.BAD_GATEWAY));
          });

          it("should write to the CEF log file", () -> {
            verify(securityEventsLogService).log(isA(RequestAuditRecord.class));
          });
        });

        describe("when audit transaction fails to commit", () -> {
          itThrowsWithMessage("rolls back commit and doesn't write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            try {
              userContext = mockUserContext(false);
              responseEntity = subject.performWithAuditing(request, userContext, auditRecordBuilder -> {
                return auditedSaveNewValueWithBadGateway(auditRecordBuilder);
              });
            } finally {
              assertThat(secretDataService.count(), equalTo(0L));

              final ArgumentCaptor<TransactionStatus> captor = ArgumentCaptor.forClass(TransactionStatus.class);
              verify(transactionManager).rollback(captor.capture());
              verify(securityEventsLogService, times(0)).log(isA(RequestAuditRecord.class));

              TransactionStatus transactionStatus = captor.getValue();
              assertThat(transactionStatus.isCompleted(), equalTo(true));
            }
          });
        });
      });
    });
  }

  private HttpServletRequest mockRequest() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeaders("X-Forwarded-For")).thenReturn(enumeration(newArrayList("1.1.1.1", "2.2.2.2")));
    when(request.getRequestURI()).thenReturn("requestURI");
    when(request.getMethod()).thenReturn("GET");
    return request;
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

  private ResponseEntity<?> auditedSaveNewValueWithBadGateway(EventAuditRecordBuilder auditRecordBuilder) {
    auditRecordBuilder.setCredentialName("keyName");
    auditRecordBuilder.setAuditingOperationCode(CREDENTIAL_ACCESS);

    NamedValueSecretData entity = new NamedValueSecretData("keyName");
    entity.setEncryptedValue("value".getBytes());
    secretDataService.save(entity);
    return new ResponseEntity<>(HttpStatus.BAD_GATEWAY);
  }

  private void checkAuditRecords(boolean successFlag, HttpStatus status) {
    final List<RequestAuditRecord> requestAuditRecords = requestAuditRecordRepository.findAll(new Sort(DESC, "now"));

    assertThat(requestAuditRecords, hasSize(1));

    RequestAuditRecord actualRequestAuditRecord = requestAuditRecords.get(0);
    assertThat(actualRequestAuditRecord.getNow(), equalTo(this.now));
    assertThat(actualRequestAuditRecord.getAuthValidFrom(), equalTo(1490903353L));
    assertThat(actualRequestAuditRecord.getAuthValidUntil(), equalTo(1550903353L));
    assertThat(actualRequestAuditRecord.getPath(), equalTo("requestURI"));
    assertThat(actualRequestAuditRecord.getClientId(), equalTo("test-client-id"));
    assertThat(actualRequestAuditRecord.getMethod(), equalTo("GET"));
    assertThat(actualRequestAuditRecord.getStatusCode(), equalTo(status.value()));

    final List<EventAuditRecord> eventAuditRecords = eventAuditRecordRepository.findAll(new Sort(DESC, "now"));

    assertThat(eventAuditRecords, hasSize(1));

    EventAuditRecord eventAuditRecord = eventAuditRecords.get(0);
    assertThat(eventAuditRecord.getCredentialName(), equalTo("keyName"));
    assertThat(eventAuditRecord.getActor(), equalTo("test-actor"));
    assertThat(eventAuditRecord.isSuccess(), equalTo(successFlag));
    assertThat(eventAuditRecord.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
    assertThat(eventAuditRecord.getRequestUuid(), equalTo(actualRequestAuditRecord.getUuid()));
    assertThat(eventAuditRecord.getRequestUuid(), notNullValue());
    assertThat(eventAuditRecord.getNow(), equalTo(this.now));
  }
}
