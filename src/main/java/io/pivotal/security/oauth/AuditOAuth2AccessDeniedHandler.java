package io.pivotal.security.oauth;

import io.pivotal.security.data.OperationAuditRecordDataService;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.service.AuditRecordBuilder;
import io.pivotal.security.service.SecurityEventsLogService;
import io.pivotal.security.util.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AuditOAuth2AccessDeniedHandler extends OAuth2AccessDeniedHandler {
  @Autowired
  ResourceServerTokenServices tokenServices;

  @Autowired
  JwtTokenStore tokenStore;

  @Autowired
  CurrentTimeProvider currentTimeProvider;

  @Autowired
  OperationAuditRecordDataService operationAuditRecordDataService;

  @Autowired
  SecurityEventsLogService securityEventsLogService;

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException authException) throws IOException, ServletException {
    try {
      super.handle(request, response, authException);
    } finally {
      String token = (String) request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE);
      OperationAuditRecord operationAuditRecord = createOperationAuditRecord(token, new AuditRecordBuilder(null, request, null), response.getStatus());
      operationAuditRecordDataService.save(operationAuditRecord);
      securityEventsLogService.log(operationAuditRecord);
    }
  }

  private OperationAuditRecord createOperationAuditRecord(String token, AuditRecordBuilder auditRecordBuilder, int status) {
    return auditRecordBuilder
        .setRequestStatus(status)
        .setAuthentication(tokenStore.readAuthentication(token))
        .setAccessToken(tokenServices.readAccessToken(token))
        .build(currentTimeProvider.getInstant());
  }
}
