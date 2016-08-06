package io.pivotal.security.service;

import java.util.Collections;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

public class AuditRecordParameters {
  private String hostName;
  private String path;
  private String requesterIp;
  private String xForwardedFor;

  public AuditRecordParameters(HttpServletRequest request) {
    this.hostName = request.getServerName();
    this.path = request.getRequestURI();
    this.requesterIp = request.getRemoteAddr();
    this.xForwardedFor = extractXForwardedFor(request.getHeaders("X-Forwarded-For"));
  }

  public AuditRecordParameters(String hostName, String path, String requesterIp, String xForwardedFor) {
    this.hostName = hostName;
    this.path = path;
    this.requesterIp = requesterIp;
    this.xForwardedFor = xForwardedFor;
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

  private String extractXForwardedFor(Enumeration<String> values) {
    return String.join(",", Collections.list(values));
  }

  @Override
  public boolean equals(Object o) {
    AuditRecordParameters other = (AuditRecordParameters) o;
    if (getHostName().equals(other.getHostName()) &&
        getPath().equals(other.getPath()) &&
        getRequesterIp().equals(other.getRequesterIp()) &&
        getXForwardedFor().equals(getXForwardedFor())) {
      return true;
    }
    return false;
  }
}