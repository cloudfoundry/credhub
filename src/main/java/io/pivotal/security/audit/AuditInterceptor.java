package io.pivotal.security.audit;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.auth.UserContextFactory;
import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.service.SecurityEventsLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuditInterceptor extends HandlerInterceptorAdapter {
  public static String REQUEST_UUID_ATTRIBUTE = "REQUEST_UUID";
  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final SecurityEventsLogService securityEventsLogService;
  private final AuditLogFactory auditLogFactory;
  private final UserContextFactory userContextFactory;

  @Autowired
  AuditInterceptor(
      RequestAuditRecordDataService requestAuditRecordDataService,
      SecurityEventsLogService securityEventsLogService,
      AuditLogFactory auditLogFactory,
      UserContextFactory userContextFactory
  ) {
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.securityEventsLogService = securityEventsLogService;
    this.auditLogFactory = auditLogFactory;
    this.userContextFactory = userContextFactory;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    if (request.getAttribute(REQUEST_UUID_ATTRIBUTE) == null) {
      request.setAttribute(REQUEST_UUID_ATTRIBUTE, UUID.randomUUID());
    }

    return super.preHandle(request, response, handler);
  }

  @Override
  public void afterCompletion(
      HttpServletRequest request,
      HttpServletResponse response,
      Object handler,
      Exception exception
  ) throws Exception {
    UserContext userContext = userContextFactory.createUserContext((Authentication) request.getUserPrincipal());

    RequestAuditRecord requestAuditRecord = auditLogFactory.createRequestAuditRecord(request, userContext, response.getStatus());

    try {
      requestAuditRecordDataService.save(requestAuditRecord);
    } finally {
      securityEventsLogService.log(requestAuditRecord);
    }
  }
}
