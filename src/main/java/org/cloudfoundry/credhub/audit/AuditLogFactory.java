package org.cloudfoundry.credhub.audit;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.auth.UserContextHolder;
import org.cloudfoundry.credhub.entity.AuthFailureAuditRecord;
import org.cloudfoundry.credhub.entity.EventAuditRecord;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

import static org.cloudfoundry.credhub.auth.UserContext.AUTH_METHOD_UAA;

@Component
public class AuditLogFactory {
  private final CurrentTimeProvider currentTimeProvider;
  private final UserContextHolder userContextHolder;
  private final RequestUuid requestUuid;

  @Autowired
  AuditLogFactory(CurrentTimeProvider currentTimeProvider,
      UserContextHolder userContextHolder, RequestUuid requestUuid) {
    this.currentTimeProvider = currentTimeProvider;
    this.userContextHolder = userContextHolder;
    this.requestUuid = requestUuid;
  }

  public RequestAuditRecord createRequestAuditRecord(HttpServletRequest request, int requestStatus) {
    return createRequestAuditRecord(request, userContextHolder.getUserContext(), requestStatus);
  }

  public RequestAuditRecord createRequestAuditRecord(HttpServletRequest request, UserContext userContext, int requestStatus) {
    return new RequestAuditRecord(
        requestUuid.getUuid(),
        currentTimeProvider.getInstant(),
        userContext.getAuthMethod(),
        userContext.getUserId(),
        userContext.getUserName(),
        userContext.getIssuer(),
        userContext.getValidFrom(),
        userContext.getValidUntil(),
        request.getServerName(),
        request.getMethod(),
        request.getRequestURI(),
        request.getQueryString(),
        requestStatus,
        request.getRemoteAddr(),
        extractXForwardedFor(request.getHeaders("X-Forwarded-For")),
        userContext.getClientId(),
        userContext.getScope(),
        userContext.getGrantType());
  }

  public AuthFailureAuditRecord createAuthFailureAuditRecord(
      HttpServletRequest request,
      Map<String, Object> tokenInformation,
      int statusCode,
      String message
  ) {
    String userId = null;
    String userName = null;
    String iss = null;
    long issued = -1;
    long expires = -1;
    String clientId = null;
    String scope = null;
    String grantType = null;

    if (tokenInformation != null) {
      userId = (String) tokenInformation.get("user_id");
      userName = (String) tokenInformation.get("user_name");
      iss = (String) tokenInformation.get("iss");
      issued = ((Number) tokenInformation.get("iat")).longValue();
      expires = ((Number) tokenInformation.get("exp")).longValue();
      clientId = (String) tokenInformation.get("client_id");
      List<String> scopeArray = (List<String>) tokenInformation.get("scope");
      scope = scopeArray == null ? null : String.join(",", scopeArray);
      grantType = (String) tokenInformation.get("grant_type");
    }

    return new AuthFailureAuditRecord()
        .setAuthMethod(AUTH_METHOD_UAA)
        .setFailureDescription(message)
        .setUserId(userId)
        .setUserName(userName)
        .setUaaUrl(iss)
        .setAuthValidFrom(issued)
        .setAuthValidUntil(expires)
        .setHostName(request.getServerName())
        .setPath(request.getRequestURI())
        .setQueryParameters(request.getQueryString())
        .setRequesterIp(request.getRemoteAddr())
        .setXForwardedFor(extractXForwardedFor(request.getHeaders("X-Forwarded-For")))
        .setClientId(clientId)
        .setScope(scope)
        .setGrantType(grantType)
        .setMethod(request.getMethod())
        .setStatusCode(statusCode);
  }

  public static EventAuditRecord createEventAuditRecord(
      EventAuditRecordParameters eventAuditRecordParameters,
      UserContext userContext,
      UUID requestUuid,
      boolean success
  ) {
    if (eventAuditRecordParameters == null) {
      eventAuditRecordParameters = new EventAuditRecordParameters();
    }

    return new EventAuditRecord(
        eventAuditRecordParameters.getAuditingOperationCode().toString(),
        eventAuditRecordParameters.getCredentialName(),
        userContext.getActor(),
        requestUuid,
        success,
        eventAuditRecordParameters.getAceOperation() != null ? eventAuditRecordParameters.getAceOperation().getOperation() : null,
        eventAuditRecordParameters.getAceActor()
    );
  }

  private static String extractXForwardedFor(Enumeration<String> values) {
    return String.join(",", Collections.list(values));
  }
}
