package io.pivotal.security.auth;

import io.pivotal.security.data.RequestAuditRecordDataService;
import io.pivotal.security.entity.RequestAuditRecord;
import io.pivotal.security.service.SecurityEventsLogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import static io.pivotal.security.audit.RequestAuditLogFactory.createRequestAuditRecord;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuditOAuth2AccessDeniedHandler extends OAuth2AccessDeniedHandler {

  private final ResourceServerTokenServices tokenServices;
  private final JwtTokenStore tokenStore;
  private final RequestAuditRecordDataService requestAuditRecordDataService;
  private final SecurityEventsLogService securityEventsLogService;

  @Autowired
  public AuditOAuth2AccessDeniedHandler(
      ResourceServerTokenServices tokenServices,
      JwtTokenStore tokenStore,
      RequestAuditRecordDataService requestAuditRecordDataService,
      SecurityEventsLogService securityEventsLogService
  ) {
    this.tokenServices = tokenServices;
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
      UserContext userContext = UserContext.fromAuthentication(tokenStore.readAuthentication(token), token, tokenServices);
      RequestAuditRecord requestAuditRecord = createRequestAuditRecord(request, userContext, response.getStatus());

      requestAuditRecordDataService.save(requestAuditRecord);
      securityEventsLogService.log(requestAuditRecord);
    }
  }

}
