package org.cloudfoundry.credhub.interceptor;

import org.cloudfoundry.credhub.audit.AuditLogFactory;
import org.cloudfoundry.credhub.audit.RequestUuid;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.cloudfoundry.credhub.data.RequestAuditRecordDataService;
import org.cloudfoundry.credhub.domain.SecurityEventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.service.SecurityEventsLogService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.springframework.security.core.Authentication;

import java.time.Instant;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.beans.SamePropertyValuesAs.samePropertyValuesAs;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class AuditInterceptorTest {
  private AuditInterceptor subject;
  private RequestAuditRecordDataService requestAuditRecordDataService;
  private SecurityEventsLogService securityEventsLogService;
  private AuditLogFactory auditLogFactory;
  private UserContextFactory userContextFactory;
  private UserContext userContext;
  private RequestUuid requestUuid;
  private HttpServletResponse response;
  private HttpServletRequest request;

  @Before
  public void setup() {
    requestAuditRecordDataService = mock(RequestAuditRecordDataService.class);
    securityEventsLogService = mock(SecurityEventsLogService.class);
    auditLogFactory = mock(AuditLogFactory.class);
    userContextFactory = mock(UserContextFactory.class);
    userContext = mock(UserContext.class);
    requestUuid = new RequestUuid();

    subject = new AuditInterceptor(
        requestAuditRecordDataService,
        securityEventsLogService,
        auditLogFactory,
        userContextFactory
    );
    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
    final Authentication authentication = mock(Authentication.class);
    when(request.getUserPrincipal()).thenReturn(authentication);

    userContext = mock(UserContext.class);
    when(userContextFactory.createUserContext(any())).thenReturn(userContext);
    when(userContext.getActor()).thenReturn("user");
  }

  @Test
  public void afterCompletion_logs_request_audit_record() throws Exception {
    final RequestAuditRecord requestAuditRecord = spy(RequestAuditRecord.class);
    when(requestAuditRecord.getNow()).thenReturn(Instant.now());

    when(response.getStatus()).thenReturn(401);

    when(auditLogFactory.createRequestAuditRecord(request, userContext, 401))
        .thenReturn(requestAuditRecord);

    subject.afterCompletion(request, response, null, null);

    ArgumentCaptor<SecurityEventAuditRecord> captor = ArgumentCaptor
        .forClass(SecurityEventAuditRecord.class);

    verify(securityEventsLogService, times(1)).log(captor.capture());
    verify(requestAuditRecordDataService, times(1)).save(requestAuditRecord);

    assertThat(captor.getValue(), samePropertyValuesAs(new SecurityEventAuditRecord(requestAuditRecord, "user")));
  }

  @Test(expected = RuntimeException.class)
  public void afterCompletion_when_request_audit_record_save_fails_still_logs_CEF_record() throws Exception {
    final RequestAuditRecord requestAuditRecord = mock(RequestAuditRecord.class);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getUserPrincipal()).thenReturn(mock(Authentication.class));

    doThrow(new RuntimeException("test"))
        .when(requestAuditRecordDataService).save(any(RequestAuditRecord.class));
    when(auditLogFactory.createRequestAuditRecord(any(HttpServletRequest.class), any(Integer.class)))
        .thenReturn(requestAuditRecord);

    try {
      subject.afterCompletion(request, mock(HttpServletResponse.class), null, null);
    } finally {
      ArgumentCaptor<SecurityEventAuditRecord> captor = ArgumentCaptor
          .forClass(SecurityEventAuditRecord.class);

      verify(securityEventsLogService).log(any());

      assertThat(captor.getValue(),
          samePropertyValuesAs(new SecurityEventAuditRecord(requestAuditRecord, "")));
    }
  }

  @Test
  public void afterCompletion_returnsIfNoUserIsPresent() throws Exception {
    when(request.getUserPrincipal()).thenReturn(null);

    subject.afterCompletion(request, response, null, null);

    verify(userContextFactory, never()).createUserContext(null);
  }
}
