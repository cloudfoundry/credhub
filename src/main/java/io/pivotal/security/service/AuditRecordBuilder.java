package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.entity.AuditingOperationCode;
import io.pivotal.security.entity.OperationAuditRecord;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Collections;
import java.util.Enumeration;

import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.entity.AuditingOperationCode.UNKNOWN_OPERATION;

public class AuditRecordBuilder {
  private String hostName;
  private String method;
  private String path;
  private String requesterIp;
  @SuppressWarnings("checkstyle:membername")
  private String xForwardedFor;
  private String queryParameters;
  private String credentialName;
  private AuditingOperationCode operationCode;
  private int requestStatus;
  private Authentication authentication;
  private boolean isSuccess;

  public AuditRecordBuilder(String credentialName,
                            HttpServletRequest request,
                            Authentication authentication) {
    setCredentialName(credentialName);
    populateFromRequest(request);
    setAuthentication(authentication);
  }

  public AuditRecordBuilder() {
  }

  public void populateFromRequest(HttpServletRequest request) {
    this.hostName = request.getServerName();
    this.method = request.getMethod();
    this.path = request.getRequestURI();
    this.queryParameters = request.getQueryString();
    this.requesterIp = request.getRemoteAddr();
    this.xForwardedFor = extractXForwardedFor(request.getHeaders("X-Forwarded-For"));
    computeOperationCode();
  }

  private static String extractXForwardedFor(Enumeration<String> values) {
    return String.join(",", Collections.list(values));
  }

  public AuditingOperationCode getOperationCode() {
    return operationCode;
  }

  public AuditRecordBuilder setOperationCode(AuditingOperationCode operationCode) {
    this.operationCode = operationCode;
    return this;
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

  public String getQueryParameters() {
    return queryParameters;
  }

  public String getCredentialName() {
    return credentialName;
  }

  public AuditRecordBuilder setCredentialName(String credentialName) {
    this.credentialName = credentialName;
    return this;
  }

  private void computeOperationCode() {
    switch (method) {
      case "GET":
        operationCode =  CREDENTIAL_ACCESS;
        break;
      case "POST":
      case "PUT":
        operationCode =  CREDENTIAL_UPDATE;
        break;
      case "DELETE":
        operationCode = CREDENTIAL_DELETE;
        break;
      default:
        operationCode = UNKNOWN_OPERATION;
    }
  }

  public AuditRecordBuilder setRequestStatus(int requestStatus) {
    this.requestStatus = requestStatus;
    return this;
  }

  public AuditRecordBuilder setAuthentication(Authentication authentication) {
    this.authentication = authentication;
    return this;
  }

  public AuditRecordBuilder setIsSuccess(boolean isSuccess) {
    this.isSuccess = isSuccess;
    return this;
  }

  public OperationAuditRecord build(Instant now, ResourceServerTokenServices tokenServices) {
    return this.build(now, null, tokenServices);
  }

  public OperationAuditRecord build(Instant now, String token,
      ResourceServerTokenServices tokenServices) {
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
