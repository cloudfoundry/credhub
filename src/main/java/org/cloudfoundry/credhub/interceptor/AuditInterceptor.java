package org.cloudfoundry.credhub.interceptor;

import java.security.Principal;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;

@Component
public class AuditInterceptor extends HandlerInterceptorAdapter {

  private static final Logger LOGGER = LogManager.getLogger("CEFAudit");
  private final UserContextFactory userContextFactory;
  private final CEFAuditRecord auditRecord;


  @Autowired
  AuditInterceptor(
    final UserContextFactory userContextFactory,
    final CEFAuditRecord auditRecord) {
    super();
    this.userContextFactory = userContextFactory;
    this.auditRecord = auditRecord;
  }

  @Override
  public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) {
    auditRecord.initCredentials();
    auditRecord.setHttpRequest(request);
    return true;
  }

  @Override
  public void afterCompletion(
    final HttpServletRequest request,
    final HttpServletResponse response,
    final Object handler,
    @Nullable final Exception exception
  ) {
    final Principal userAuth = request.getUserPrincipal();
    if (userAuth == null) {
      return;
    }
    final UserContext userContext = userContextFactory.createUserContext((Authentication) userAuth);

    auditRecord.setUsername(userAuth.getName());
    auditRecord.setHttpStatusCode(response.getStatus());
    auditRecord.setUserGuid(userContext.getActor());
    auditRecord.setAuthMechanism(userContext.getAuthMethod());

    LOGGER.info(auditRecord.toString());
  }
}
