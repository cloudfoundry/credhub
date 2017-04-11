package io.pivotal.security.auth;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.audit.AuditRecordBuilder;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class AuditOAuth2AccessDeniedHandler extends OAuth2AccessDeniedHandler {

  private final ResourceServerTokenServices tokenServices;
  private final JwtTokenStore tokenStore;
  private final CurrentTimeProvider currentTimeProvider;
  private final OperationAuditRecordDataService operationAuditRecordDataService;
  private final SecurityEventsLogService securityEventsLogService;

  @Autowired
  public AuditOAuth2AccessDeniedHandler(
      ResourceServerTokenServices tokenServices,
      JwtTokenStore tokenStore,
      CurrentTimeProvider currentTimeProvider,
      OperationAuditRecordDataService operationAuditRecordDataService,
      SecurityEventsLogService securityEventsLogService
  ) {
    this.tokenServices = tokenServices;
    this.tokenStore = tokenStore;
    this.currentTimeProvider = currentTimeProvider;
    this.operationAuditRecordDataService = operationAuditRecordDataService;
    this.securityEventsLogService = securityEventsLogService;
  }

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException authException) throws IOException, ServletException {
    try {
      super.handle(request, response, authException);
    } finally {
      String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);
      UserContext usercontext = UserContext.fromAuthentication(tokenStore.readAuthentication(token), token, tokenServices);
      Collection<OperationAuditRecord> operationAuditRecords = new AuditRecordBuilder(null, request, usercontext)
          .setRequestStatus(response.getStatus())
          .build(currentTimeProvider.getInstant());

      operationAuditRecords.forEach((record) -> {
        operationAuditRecordDataService.save(record);
        securityEventsLogService.log(record);
      });
    }
  }

}
