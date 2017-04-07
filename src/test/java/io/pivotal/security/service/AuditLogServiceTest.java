package io.pivotal.security.service;

import com.greghaskins.spectrum.Spectrum;
import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.NamedValueSecretData;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.exceptions.AuditSaveFailureException;
import io.pivotal.security.fake.FakeRepository;
import io.pivotal.security.fake.FakeTransactionManager;
import io.pivotal.security.util.CurrentTimeProvider;
import org.assertj.core.util.Lists;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.security.Principal;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;

import static com.greghaskins.spectrum.Spectrum.beforeEach;
import static com.greghaskins.spectrum.Spectrum.describe;
import static com.greghaskins.spectrum.Spectrum.it;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.helper.SpectrumHelper.itThrowsWithMessage;
import static io.pivotal.security.util.CurrentTimeProvider.makeCalendar;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(Spectrum.class)
@SuppressWarnings("EmptyCatchBlock")
public class AuditLogServiceTest {

  private AuditLogService subject;
  private OperationAuditRecordDataService operationAuditRecordDataService;
  private FakeRepository fakeRepository;
  private FakeTransactionManager transactionManager;
  private CurrentTimeProvider currentTimeProvider;
  private SecurityEventsLogService securityEventsLogService;

  private final Instant now = Instant.ofEpochSecond(1490903353L);
  private final Instant then = Instant.ofEpochSecond(1550903353L);

  private ResponseEntity<?> responseEntity;
  private PreAuthenticatedAuthenticationToken authentication;

  {

    beforeEach(() -> {
      operationAuditRecordDataService = mock(OperationAuditRecordDataService.class);
      currentTimeProvider = mock(CurrentTimeProvider.class);
      securityEventsLogService = mock(SecurityEventsLogService.class);
      transactionManager = new FakeTransactionManager();
      authentication = mockMtlsAuthentication();
      fakeRepository = new FakeRepository(transactionManager);

      when(operationAuditRecordDataService.save(isA(OperationAuditRecord.class))).thenAnswer(answer -> {
        return answer.getArgumentAt(0, OperationAuditRecord.class);
      });

      when(currentTimeProvider.getInstant()).thenReturn(now);
      when(currentTimeProvider.getNow()).thenReturn(makeCalendar(now.toEpochMilli()));

      subject = new AuditLogService(
          currentTimeProvider,
          null,
          operationAuditRecordDataService,
          transactionManager,
          securityEventsLogService
      );
    });

    describe("logging behavior", () -> {
      describe("when the action succeeds", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing(auditRecordBuilder -> {
              return auditedSaveAndReturnNewValue(auditRecordBuilder);
            });
          });

          it("performs the action", () -> {
            assertThat(fakeRepository.count(), equalTo(1L));
          });

          it("passes the request untouched", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.OK));
          });

          it("logs audit entry", () -> {
            checkAuditRecord(true, HttpStatus.OK);
          });

          it("logs in CEF format to file", () -> {
            verify(securityEventsLogService).log(isA(OperationAuditRecord.class));
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("does not perform the action or write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            doThrow(new RuntimeException()).when(operationAuditRecordDataService)
                .save(any(OperationAuditRecord.class));

            try {
              responseEntity = subject.performWithAuditing(auditRecordBuilder -> {
                return auditedSaveAndReturnNewValue(auditRecordBuilder);
              });
            } finally {
              assertThat(fakeRepository.count(), equalTo(0L));
              verify(securityEventsLogService, times(0)).log(isA(OperationAuditRecord.class));
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
              subject.performWithAuditing(auditRecordBuilder -> {
                auditRecordBuilder.setCredentialName("keyName");
                auditRecordBuilder.populateFromRequest(
                    new MockHttpServletRequest("GET", "requestURI"));
                auditRecordBuilder.setAuthentication(authentication);

                NamedValueSecretData entity = new NamedValueSecretData("keyName");
                entity.setEncryptedValue("value".getBytes());
                fakeRepository.save(entity);
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
            checkAuditRecord(false, HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(fakeRepository.count(), equalTo(0L));
          });

          it("should write to the CEF log file", () -> {
            verify(securityEventsLogService).log(isA(OperationAuditRecord.class));
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("rolls back commit and doesn't write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            doThrow(new RuntimeException()).when(operationAuditRecordDataService)
                .save(any(OperationAuditRecord.class));

            try {
              responseEntity = subject.performWithAuditing(auditRecordBuilder -> {
                auditRecordBuilder.setCredentialName("keyName");
                auditRecordBuilder.populateFromRequest(
                    new MockHttpServletRequest("GET", "requestURI"));
                auditRecordBuilder.setAuthentication(authentication);

                NamedValueSecretData entity = new NamedValueSecretData("keyName");
                entity.setEncryptedValue("value".getBytes());
                fakeRepository.save(entity);
                throw new RuntimeException("controller method failed");
              });
            } finally {
              assertThat(transactionManager.hasOpenTransaction(), is(false));
              assertThat(fakeRepository.count(), equalTo(0L));

              verify(securityEventsLogService, times(0)).log(isA(OperationAuditRecord.class));
            }
          });
        });
      });

      describe("when the action fails with a non 200 status", () -> {
        describe("when the audit succeeds", () -> {
          beforeEach(() -> {
            responseEntity = subject.performWithAuditing(auditRecordBuilder -> {
              return auditedSaveNewValueWithBadGateway(auditRecordBuilder);
            });
          });

          it("logs audit entry for failure", () -> {
            checkAuditRecord(false, HttpStatus.BAD_GATEWAY);
            assertThat(fakeRepository.count(), equalTo(0L));
          });

          it("returns the non-2xx status code", () -> {
            assertThat(responseEntity.getStatusCode(), equalTo(HttpStatus.BAD_GATEWAY));
          });

          it("should write to the CEF log file", () -> {
            verify(securityEventsLogService).log(isA(OperationAuditRecord.class));
          });
        });

        describe("when the database audit fails", () -> {
          itThrowsWithMessage("rolls back commit and doesn't write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            doThrow(new RuntimeException()).when(operationAuditRecordDataService)
                .save(any(OperationAuditRecord.class));

            try {
              responseEntity = subject.performWithAuditing(auditRecordBuilder -> {
                return auditedSaveNewValueWithBadGateway(auditRecordBuilder);
              });
            } finally {
              assertThat(transactionManager.hasOpenTransaction(), is(false));
              assertThat(fakeRepository.count(), equalTo(0L));

              verify(securityEventsLogService, times(0)).log(isA(OperationAuditRecord.class));
            }
          });
        });

        describe("when audit transaction fails to commit", () -> {
          itThrowsWithMessage("rolls back commit and doesn't write to the CEF log", AuditSaveFailureException.class, "error.audit_save_failure", () -> {
            try {
              transactionManager.failOnCommit();
              responseEntity = subject.performWithAuditing(auditRecordBuilder -> {
                return auditedSaveNewValueWithBadGateway(auditRecordBuilder);
              });
            } finally {
              assertThat(transactionManager.hasOpenTransaction(), is(false));
              assertThat(fakeRepository.count(), equalTo(0L));

              verify(securityEventsLogService, times(0)).log(isA(OperationAuditRecord.class));
            }
          });
        });
      });
    });
  }

  private PreAuthenticatedAuthenticationToken mockMtlsAuthentication() {
    Principal principal = mock(Principal.class);
    when(principal.getName()).thenReturn("distinguished name");

    X509Certificate certificate = mock(X509Certificate.class);
    when(certificate.getNotBefore()).thenReturn(Date.from(now));
    when(certificate.getNotAfter()).thenReturn(Date.from(then));
    when(certificate.getSubjectDN()).thenReturn(principal);

    PreAuthenticatedAuthenticationToken authentication = mock(PreAuthenticatedAuthenticationToken.class);
    when(authentication.getCredentials()).thenReturn(certificate);
    when(authentication.getAuthorities()).thenReturn(Lists.emptyList());

    return authentication;
  }

  private ResponseEntity<?> auditedSaveAndReturnNewValue(
      AuditRecordBuilder auditRecordBuilder) {
    auditRecordBuilder.setCredentialName("keyName");
    auditRecordBuilder.populateFromRequest(
        new MockHttpServletRequest("GET", "requestURI"));
    auditRecordBuilder.setAuthentication(authentication);
    NamedValueSecretData entity = new NamedValueSecretData("keyName");
    entity.setEncryptedValue("value".getBytes());
    final NamedValueSecretData secret = fakeRepository.save(entity);
    return new ResponseEntity<>(secret, HttpStatus.OK);
  }

  private ResponseEntity<?> auditedSaveNewValueWithBadGateway(
      AuditRecordBuilder auditRecordBuilder) {
    auditRecordBuilder.setCredentialName("keyName");
    auditRecordBuilder.populateFromRequest(
        new MockHttpServletRequest("GET", "requestURI"));
    auditRecordBuilder.setAuthentication(authentication);

    NamedValueSecretData entity = new NamedValueSecretData("keyName");
    entity.setEncryptedValue("value".getBytes());
    fakeRepository.save(entity);
    return new ResponseEntity<>(HttpStatus.BAD_GATEWAY);
  }

  private void checkAuditRecord(boolean successFlag, HttpStatus status) {
    ArgumentCaptor<OperationAuditRecord> recordCaptor = ArgumentCaptor
        .forClass(OperationAuditRecord.class);
    verify(operationAuditRecordDataService, times(1)).save(recordCaptor.capture());

    OperationAuditRecord actual = recordCaptor.getValue();
    assertThat(actual.getNow(), equalTo(now));
    assertThat(actual.getCredentialName(), equalTo("keyName"));
    assertThat(actual.getOperation(), equalTo(CREDENTIAL_ACCESS.toString()));
    assertThat(actual.getAuthValidFrom(), equalTo(1490903353L));
    assertThat(actual.getAuthValidUntil(), equalTo(1550903353L));
    assertThat(actual.getPath(), equalTo("requestURI"));
    assertThat(actual.isSuccess(), equalTo(successFlag));
    assertThat(actual.getClientId(), equalTo("distinguished name"));
    assertThat(actual.getMethod(), equalTo("GET"));
    assertThat(actual.getStatusCode(), equalTo(status.value()));
  }
}
