package org.cloudfoundry.credhub.auth;

import org.cloudfoundry.credhub.audit.AuditLogFactory;
import org.cloudfoundry.credhub.data.RequestAuditRecordDataService;
import org.cloudfoundry.credhub.domain.SecurityEventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.service.SecurityEventsLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
@ConditionalOnProperty(value = "security.oauth2.enabled")
public class AuditOAuth2AccessDeniedHandler extends OAuth2AccessDeniedHandler {

  private final TokenStore tokenStore;
  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final SecurityEventsLogService securityEventsLogService;
  private final UserContextFactory userContextFactory;
  private final AuditLogFactory auditLogFactory;
  private MessageSourceAccessor messageSourceAccessor;
  private final WebResponseExceptionTranslator exceptionTranslator;

  @Autowired
  public AuditOAuth2AccessDeniedHandler(
      TokenStore tokenStore,
      RequestAuditRecordDataService requestAuditRecordDataService,
      SecurityEventsLogService securityEventsLogService,
      UserContextFactory userContextFactory,
      WebResponseExceptionTranslator exceptionTranslator,
      AuditLogFactory auditLogFactory,
      MessageSourceAccessor messageSourceAccessor
  ) {
    this.userContextFactory = userContextFactory;
    this.tokenStore = tokenStore;
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.securityEventsLogService = securityEventsLogService;
    this.exceptionTranslator = exceptionTranslator;
    this.auditLogFactory = auditLogFactory;
    this.messageSourceAccessor = messageSourceAccessor;
  }

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException authException) throws IOException, ServletException {
    try {
      super.handle(request, response, authException);
    } finally {
      String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);
      UserContext userContext = userContextFactory.createUserContext(tokenStore.readAuthentication(token), token);
      RequestAuditRecord requestAuditRecord = auditLogFactory.createRequestAuditRecord(
          request,
          userContext,
          response.getStatus()
      );

      requestAuditRecordDataService.save(requestAuditRecord);
      securityEventsLogService.log(new SecurityEventAuditRecord(requestAuditRecord, userContext.getActor()));
    }
  }

  @Override
  protected ResponseEntity<OAuth2Exception> enhanceResponse(ResponseEntity<OAuth2Exception> result, Exception authException) {
    if (authException.getCause() instanceof InsufficientScopeException) {
      try {
        String errorMessage = messageSourceAccessor.getMessage("error.oauth.insufficient_scope");
        return this.exceptionTranslator.translate(new AccessDeniedException(errorMessage));
      } catch (Exception e) {
        return result;
      }
    } else {
      return result;
    }
  }
}
