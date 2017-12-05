package org.cloudfoundry.credhub.interceptor;

import org.cloudfoundry.credhub.audit.AuditLogFactory;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.cloudfoundry.credhub.data.RequestAuditRecordDataService;
import org.cloudfoundry.credhub.domain.SecurityEventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.service.SecurityEventsLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuditInterceptor extends HandlerInterceptorAdapter {

  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final SecurityEventsLogService securityEventsLogService;
  private final AuditLogFactory auditLogFactory;
  private final UserContextFactory userContextFactory;

  @Autowired
  AuditInterceptor(
      RequestAuditRecordDataService requestAuditRecordDataService,
      SecurityEventsLogService securityEventsLogService,
      AuditLogFactory auditLogFactory,
      UserContextFactory userContextFactory) {
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.securityEventsLogService = securityEventsLogService;
    this.auditLogFactory = auditLogFactory;
    this.userContextFactory = userContextFactory;
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
      securityEventsLogService.log(new SecurityEventAuditRecord(requestAuditRecord, userContext.getActor()));
    }
  }
}
