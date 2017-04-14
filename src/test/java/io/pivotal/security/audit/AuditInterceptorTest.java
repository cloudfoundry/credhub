package io.pivotal.security.audit;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextFactory;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.service.SecurityEventsLogService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.security.core.Authentication;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(JUnit4.class)
public class AuditInterceptorTest {
  private AuditInterceptor subject;
  private RequestAuditRecordDataService requestAuditRecordDataService;
  private SecurityEventsLogService securityEventsLogService;
  private RequestAuditLogFactory requestAuditLogFactory;
  private UserContextFactory userContextFactory;

  @Before
  public void setup() {
    requestAuditRecordDataService = mock(RequestAuditRecordDataService.class);
    securityEventsLogService = mock(SecurityEventsLogService.class);
    requestAuditLogFactory = mock(RequestAuditLogFactory.class);
    userContextFactory = mock(UserContextFactory.class);

    subject = new AuditInterceptor(
        requestAuditRecordDataService,
        securityEventsLogService,
        requestAuditLogFactory,
        userContextFactory
    );
  }

  @Test
  public void preHandle_sets_request_uuid_if_not_already_set() throws Exception {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    subject.preHandle(request, null, null);

    verify(request).setAttribute(eq("REQUEST_UUID"), any(UUID.class));
  }

  @Test
  public void preHandle_does_not_override_existing_uuid() throws Exception {
    final UUID originalUuid = UUID.randomUUID();
    final HttpServletRequest request = mock(HttpServletRequest.class);

    when(request.getAttribute("REQUEST_UUID")).thenReturn(originalUuid);

    subject.preHandle(request, null, null);

    verify(request, times(0)).setAttribute(any(String.class), any());
  }

  @Test
  public void afterCompletion_logs_request_audit_record() throws Exception {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    final HttpServletResponse response = mock(HttpServletResponse.class);
    final Authentication authentication = mock(Authentication.class);
    final UserContext userContext = mock(UserContext.class);
    final RequestAuditRecord requestAuditRecord = spy(RequestAuditRecord.class);

    when(request.getUserPrincipal()).thenReturn(authentication);
    when(userContextFactory.createUserContext(authentication)).thenReturn(userContext);
    when(response.getStatus()).thenReturn(401);

    when(requestAuditLogFactory.createRequestAuditRecord(request, userContext, 401))
        .thenReturn(requestAuditRecord);

    subject.afterCompletion(request, response, null, null);

    assertThat(requestAuditRecord.getStatusCode(), equalTo(401));

    verify(securityEventsLogService, times(1)).log(requestAuditRecord);
    verify(requestAuditRecordDataService, times(1)).save(requestAuditRecord);
  }

  @Test
  public void afterCompletion_rethrows_if_provided_with_exception() {
    final Exception expectedException = new RuntimeException("EXPECTED");
    final HttpServletRequest request = mock(HttpServletRequest.class);
    final HttpServletResponse response = mock(HttpServletResponse.class);

    when(requestAuditLogFactory.createRequestAuditRecord(any(HttpServletRequest.class), any(UserContext.class), any(Integer.class)))
        .thenReturn(mock(RequestAuditRecord.class));

    try {
      subject.afterCompletion(request, response, null, expectedException);
      fail("Expected exception to be thrown");
    } catch (Exception e) {
      assertThat(e, equalTo(expectedException));
    }
  }
}
