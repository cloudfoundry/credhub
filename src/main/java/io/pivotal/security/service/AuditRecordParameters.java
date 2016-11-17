package io.pivotal.security.service;

import org.springframework.security.core.Authentication;

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
  private final String credentialName;

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

  public String getCredentialName() {
    return credentialName;
  }

}
