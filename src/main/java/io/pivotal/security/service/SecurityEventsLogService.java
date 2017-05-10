package io.pivotal.security.service;

import io.pivotal.security.config.VersionProvider;
import io.pivotal.security.domain.SecurityEventAuditRecord;
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

  public void log(SecurityEventAuditRecord securityEventAuditRecord) {
    String signature = securityEventAuditRecord.getSignature();
    String header = String
        .join("|", "CEF:0|cloud_foundry|credhub", versionProvider.getVersion(), signature,
            signature, "0");
    String message = String.join(
        " ",
        "rt=" + securityEventAuditRecord.getTime(),
        "suser=" + securityEventAuditRecord.getUserName(),
        "suid=" + securityEventAuditRecord.getActor(),
        "cs1Label=userAuthenticationMechanism",
        "cs1=" + securityEventAuditRecord.determineCs1(),
        "request=" + securityEventAuditRecord.getPathWithQueryParameters(),
        "requestMethod=" + securityEventAuditRecord.getMethod(),
        "cs3Label=result",
        "cs3=" + securityEventAuditRecord.getResultCode(),
        "cs4Label=httpStatusCode",
        "cs4=" + securityEventAuditRecord.getStatusCode(),
        "src=" + securityEventAuditRecord.getRequesterIp(),
        "dst=" + securityEventAuditRecord.getHostName()
    );

    securityEventsLogger.info(String.join("|", header, message));
  }
}
