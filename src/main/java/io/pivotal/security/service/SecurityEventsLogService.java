package io.pivotal.security.service;

import io.pivotal.security.config.VersionProvider;
import io.pivotal.security.entity.OperationAuditRecord;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventsLogService {
  private final Logger securityEventsLogger;
  private final VersionProvider versionProvider;

  @Autowired
  SecurityEventsLogService(Logger securityEventsLogger, VersionProvider versionProvider) {
    this.securityEventsLogger = securityEventsLogger;
    this.versionProvider = versionProvider;
  }

  public void log(OperationAuditRecord operationAuditRecord) {
    String signature = operationAuditRecord.getMethod() + " " + operationAuditRecord.getPath();
    String header = String.join("|", "CEF:0|cloud_foundry|credhub", versionProvider.getVersion(), signature, signature, "0");
    String message = String.join(
        " ",
        "rt=" + String.valueOf(operationAuditRecord.getNow().toEpochMilli()),
        "suser=" + operationAuditRecord.getUserName(),
        "suid=" + operationAuditRecord.getUserId(),
        "cs1Label=userAuthenticationMechanism",
        "cs1=auth-access-token",
        "request=" + getPathWithQueryParameters(operationAuditRecord),
        "requestMethod=" + operationAuditRecord.getMethod(),
        "cs3Label=result",
        "cs3=" + getResultCode(operationAuditRecord.getStatusCode()),
        "cs4Label=httpStatusCode",
        "cs4=" + operationAuditRecord.getStatusCode(),
        "src=" + operationAuditRecord.getRequesterIp(),
        "dst=" + operationAuditRecord.getHostName()
    );

    securityEventsLogger.info(String.join("|", header, message));
  }

  private String getPathWithQueryParameters(OperationAuditRecord operationAuditRecord) {
    String queryParameters = operationAuditRecord.getQueryParameters();
    String path = operationAuditRecord.getPath();

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
