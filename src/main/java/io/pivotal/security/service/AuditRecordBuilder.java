package io.pivotal.security.service;

import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.entity.OperationAuditRecord;
import io.pivotal.security.oauth.UserContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;

import static io.pivotal.security.entity.AuditingOperationCode.*;

public class AuditRecordBuilder {
  private final String hostName;
  private final String method;
  private final String path;
  private final String requesterIp;
  private final String xForwardedFor;
  private final String queryParameters;
  private String credentialName;
  private AuditingOperationCode operationCode;
  private int requestStatus;
  private OAuth2AccessToken accessToken;
  private Authentication authentication;
  private boolean isSuccess;

  public AuditRecordBuilder(String credentialName,
                            HttpServletRequest request,
                            Authentication authentication) {
    this.credentialName = credentialName;
    this.hostName = request.getServerName();
    this.method = request.getMethod();
    this.path = request.getRequestURI();
    this.queryParameters = request.getQueryString();
    this.requesterIp = request.getRemoteAddr();
    this.xForwardedFor = extractXForwardedFor(request.getHeaders("X-Forwarded-For"));
    this.authentication = authentication;
    this.operationCode = computeOperationCode();
  }

  public AuditingOperationCode getOperationCode() {
    return operationCode;
  }

  public String getHostName() {
    return hostName;
  }

  public String getMethod() {
    return method;
  }

  public String getPath() {
    return path;
  }

  public String getRequesterIp() {
    return requesterIp;
  }

  public String getXForwardedFor() {
    return xForwardedFor;
  }

  private static String extractXForwardedFor(Enumeration<String> values) {
    return String.join(",", Collections.list(values));
  }

  public String getQueryParameters() {
    return queryParameters;
  }

  public AuditRecordBuilder setCredentialName(String credentialName) {
    this.credentialName = credentialName;
    return this;
  }

  public String getCredentialName() {
    return credentialName;
  }

  private AuditingOperationCode computeOperationCode() {
    switch (method) {
      case "GET":
        return CREDENTIAL_ACCESS;
      case "POST":
      case "PUT":
        return CREDENTIAL_UPDATE;
      case "DELETE":
        return CREDENTIAL_DELETE;
      default:
        return UNKNOWN_OPERATION;
    }
  }

  public AuditRecordBuilder setRequestStatus(int requestStatus) {
    this.requestStatus = requestStatus;
    return this;
  }

  public AuditRecordBuilder setAuthentication(OAuth2Authentication authentication) {
    this.authentication = authentication;
    return this;
  }

  public AuditRecordBuilder setIsSuccess(boolean isSuccess) {
    this.isSuccess = isSuccess;
    return this;
  }

  public AuditRecordBuilder setOperationCode(AuditingOperationCode operationCode) {
    this.operationCode = operationCode;
    return this;
  }

  public OperationAuditRecord build(Instant now, ResourceServerTokenServices tokenServices) {
    return this.build(now, null, tokenServices);
  }

  public OperationAuditRecord build(Instant now, String token, ResourceServerTokenServices tokenServices) {
    UserContext user = UserContext.fromAuthentication(authentication, token, tokenServices);

    return new OperationAuditRecord(
      user.getAuthMethod(),
      now,
      getCredentialName(),
      getOperationCode().toString(),
      user.getUserId(),
      user.getUserName(),
      user.getIssuer(),
      user.getValidFrom(),
      user.getValidUntil(),
      getHostName(),
      method,
      path,
      getQueryParameters(),
      requestStatus,
      getRequesterIp(),
      getXForwardedFor(),
      user.getClientId(),
      user.getScope(),
      user.getGrantType(),
      isSuccess
    );
  }

}
