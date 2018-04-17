package org.cloudfoundry.credhub.interceptor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.audit.CEFAuditRecord;
import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class AuditInterceptor extends HandlerInterceptorAdapter {

  private final Logger logger = LogManager.getLogger("CEFAudit");
  private final UserContextFactory userContextFactory;
  private final CEFAuditRecord auditRecord;


  @Autowired
  AuditInterceptor(
      UserContextFactory userContextFactory,
      CEFAuditRecord auditRecord) {
    this.userContextFactory = userContextFactory;
    this.auditRecord = auditRecord;
  }

  @Override
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    auditRecord.initCredentials();
    auditRecord.setHttpRequest(request);
    return true;
  }

  @Override
  public void afterCompletion(
      HttpServletRequest request,
      HttpServletResponse response,
      Object handler,
      Exception exception) {
    Principal userAuth = request.getUserPrincipal();
    if (userAuth == null) {
      return;
    }
    UserContext userContext = userContextFactory.createUserContext((Authentication) userAuth);

    auditRecord.setUsername(userAuth.getName());
    auditRecord.setHttpStatusCode(response.getStatus());
    auditRecord.setUserGuid(userContext.getActor());
    auditRecord.setAuthMechanism(userContext.getAuthMethod());

    logger.info(auditRecord.toString());
  }
}
