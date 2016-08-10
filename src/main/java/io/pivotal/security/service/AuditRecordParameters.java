package io.pivotal.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

public class AuditRecordParameters {
  private final String hostName;
  private final String path;
  private final String requesterIp;
  private final String xForwardedFor;
  private final Authentication authentication;

  @Autowired
  ResourceServerTokenServices tokenServices;

  public AuditRecordParameters(HttpServletRequest request, Authentication authentication) {
    this(
        request.getServerName(),
        request.getRequestURI(),
        request.getRemoteAddr(),
        extractXForwardedFor(request.getHeaders("X-Forwarded-For")),
        authentication
    );
  }

  AuditRecordParameters(String hostName, String path, String requesterIp, String xForwardedFor, Authentication authentication) {
    this.hostName = hostName;
    this.path = path;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
    this.authentication = authentication;
  }

  public String getHostName() {
    return hostName;
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
}