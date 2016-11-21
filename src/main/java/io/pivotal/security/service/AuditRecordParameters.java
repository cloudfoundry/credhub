package io.pivotal.security.service;

import io.pivotal.security.entity.AuditingOperationCode;
import org.springframework.security.core.Authentication;

import static io.pivotal.security.controller.v1.CaController.API_V1_CA;
import static io.pivotal.security.entity.AuditingOperationCode.CA_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CA_UPDATE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_ACCESS;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_DELETE;
import static io.pivotal.security.entity.AuditingOperationCode.CREDENTIAL_UPDATE;
import static io.pivotal.security.entity.AuditingOperationCode.UNKNOWN_OPERATION;

import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

public class AuditRecordParameters {
  private final String hostName;
  private final String method;
  private final String path;
  private final String requesterIp;
  private final String xForwardedFor;
  private final Authentication authentication;
  private final String queryParameters;
  private String credentialName;
  private AuditingOperationCode operationCode;

  public AuditRecordParameters(String credentialName,
                               HttpServletRequest request,
                               Authentication authentication) {
    this(
        request.getServerName(),
        credentialName,
        request.getMethod(),
        request.getRequestURI(),
        request.getQueryString(),
        request.getRemoteAddr(),
        extractXForwardedFor(request.getHeaders("X-Forwarded-For")),
        authentication
    );
  }

  AuditRecordParameters(String hostName,
                        String credentialName,
                        String method,
                        String path,
                        String queryParameters,
                        String requesterIp,
                        String xForwardedFor,
                        Authentication authentication) {
    this.hostName = hostName;
    this.credentialName = credentialName;
    this.method = method;
    this.path = path;
    this.queryParameters = queryParameters;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
    this.authentication = authentication;
    this.operationCode = computeOperationCode();
  }

  public AuditRecordParameters(AuditingOperationCode operationCode, String secretName, HttpServletRequest request, Authentication authentication) {
    this(secretName, request, authentication);
    this.operationCode = operationCode;
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

  public Authentication getAuthentication() {
    return authentication;
  }

  private static String extractXForwardedFor(Enumeration<String> values) {
    return String.join(",", Collections.list(values));
  }

  public String getQueryParameters() {
    return queryParameters;
  }

  public void setCredentialName(String credentialName) {
    this.credentialName = credentialName;
  }

  public String getCredentialName() {
    return credentialName;
  }

  private AuditingOperationCode computeOperationCode() {
    boolean isCa = path.contains(API_V1_CA) ? true : false;
    switch (method) {
      case "GET":
        return isCa ? CA_ACCESS : CREDENTIAL_ACCESS;
      case "POST":
      case "PUT":
        return isCa ? CA_UPDATE : CREDENTIAL_UPDATE;
      case "DELETE":
        return isCa ? UNKNOWN_OPERATION : CREDENTIAL_DELETE;
      default:
        return UNKNOWN_OPERATION;
    }
  }
}
