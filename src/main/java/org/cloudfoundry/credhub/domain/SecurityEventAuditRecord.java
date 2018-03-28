package org.cloudfoundry.credhub.domain;

import org.cloudfoundry.credhub.auth.UserContext;
import org.cloudfoundry.credhub.entity.RequestAuditRecord;
import org.apache.commons.lang3.StringUtils;

public class SecurityEventAuditRecord {

  private RequestAuditRecord delegate;
  private String actor;

  public SecurityEventAuditRecord(RequestAuditRecord delegate, String actor) {
    this.delegate = delegate;
    this.actor = actor;
  }

  public String determineCs1() {
    final boolean isMutualTls = UserContext.AUTH_METHOD_MUTUAL_TLS
        .equals(delegate.getAuthMethod());
    return isMutualTls ? "mutual-tls" : "oauth-access-token";
  }

  public String getPathWithQueryParameters() {
    String queryParameters = delegate.getQueryParameters();
    String path = delegate.getPath();

    return StringUtils.isEmpty(queryParameters) ? path : String.join("?", path, queryParameters);
  }

  public String getResultCode() {
    int statusCode = delegate.getStatusCode();
    if (statusCode <= 199) {
      return "info";
    } else if (statusCode <= 299) {
      return "success";
    } else if (statusCode <= 399) {
      return "redirect";
    } else if (statusCode <= 499) {
      return "clientError";
    } else {
      return "serverError";
    }
  }

  public String getSignature() {
    return delegate.getMethod() + " " + delegate.getPath();
  }

  public String getTime() {
    return String.valueOf(delegate.getNow().toEpochMilli());
  }

  public String getUserName() {
    return delegate.getUserName();
  }

  public String getActor() {
    return actor;
  }

  public String getMethod() {
    return delegate.getMethod();
  }

  public int getStatusCode() {
    return delegate.getStatusCode();
  }

  public String getRequesterIp() {
    return delegate.getRequesterIp();
  }

  public String getHostName() {
    return delegate.getHostName();
  }
}
