package io.pivotal.security.service;

import io.pivotal.security.auth.UserContext;
import io.pivotal.security.entity.RequestAuditRecord;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventsLogService {

  private final Logger securityEventsLogger;
  private final String credhubVersion;

  @Autowired
  SecurityEventsLogService(Logger securityEventsLogger, @Value("${info.app.version}") String credhubVersion) {
    this.securityEventsLogger = securityEventsLogger;
    this.credhubVersion = credhubVersion;
  }

  public void log(RequestAuditRecord requestAuditRecord) {
    String signature = requestAuditRecord.getMethod() + " " + requestAuditRecord.getPath();
    String header = String
        .join("|", "CEF:0|cloud_foundry|credhub", credhubVersion, signature,
            signature, "0");
    String message = String.join(
        " ",
        "rt=" + String.valueOf(requestAuditRecord.getNow().toEpochMilli()),
        "suser=" + requestAuditRecord.getUserName(),
        "suid=" + requestAuditRecord.getUserId(),
        "cs1Label=userAuthenticationMechanism",
        "cs1=" + determineCs1(requestAuditRecord),
        "request=" + getPathWithQueryParameters(requestAuditRecord),
        "requestMethod=" + requestAuditRecord.getMethod(),
        "cs3Label=result",
        "cs3=" + getResultCode(requestAuditRecord.getStatusCode()),
        "cs4Label=httpStatusCode",
        "cs4=" + requestAuditRecord.getStatusCode(),
        "src=" + requestAuditRecord.getRequesterIp(),
        "dst=" + requestAuditRecord.getHostName()
    );

    securityEventsLogger.info(String.join("|", header, message));
  }

  private String determineCs1(RequestAuditRecord requestAuditRecord) {
    final boolean isMutualTls = UserContext.AUTH_METHOD_MUTUAL_TLS
        .equals(requestAuditRecord.getAuthMethod());
    return isMutualTls ? "mutual-tls" : "oauth-access-token";
  }

  private String getPathWithQueryParameters(RequestAuditRecord requestAuditRecord) {
    String queryParameters = requestAuditRecord.getQueryParameters();
    String path = requestAuditRecord.getPath();

    return StringUtils.isEmpty(queryParameters) ? path : String.join("?", path, queryParameters);
  }

  private String getResultCode(int statusCode) {
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
}
