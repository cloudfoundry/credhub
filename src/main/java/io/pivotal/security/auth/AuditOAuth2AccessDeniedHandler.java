package io.pivotal.security.auth;

import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.service.SecurityEventsLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static io.pivotal.security.audit.RequestAuditLogFactory.createRequestAuditRecord;

public class AuditOAuth2AccessDeniedHandler extends OAuth2AccessDeniedHandler {

  private final JwtTokenStore tokenStore;
  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final SecurityEventsLogService securityEventsLogService;
  private final UserContextFactory userContextFactory;

  @Autowired
  public AuditOAuth2AccessDeniedHandler(
      JwtTokenStore tokenStore,
      RequestAuditRecordDataService requestAuditRecordDataService,
      SecurityEventsLogService securityEventsLogService,
      UserContextFactory userContextFactory
  ) {
    this.userContextFactory = userContextFactory;
    this.tokenStore = tokenStore;
    this.requestAuditRecordDataService = requestAuditRecordDataService;
    this.securityEventsLogService = securityEventsLogService;
  }

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException authException) throws IOException, ServletException {
    try {
      super.handle(request, response, authException);
    } finally {
      String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);
      UserContext userContext = userContextFactory.createUserContext(tokenStore.readAuthentication(token), token);
      RequestAuditRecord requestAuditRecord = createRequestAuditRecord(request, userContext, response.getStatus());

      requestAuditRecordDataService.save(requestAuditRecord);
      securityEventsLogService.log(requestAuditRecord);
    }
  }

}
