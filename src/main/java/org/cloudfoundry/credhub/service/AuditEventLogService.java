package org.cloudfoundry.credhub.service;

import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.VersionProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;

public class AuditEventLogService {

  private String credhubVersion;
  private Logger securityEventsLogger;

  @Autowired
  public AuditEventLogService(VersionProvider versionProvider, Logger securityEventsLogger){
    this.credhubVersion = versionProvider.currentVersion();
    this.securityEventsLogger = securityEventsLogger;
  }

  public void log(HttpRequest request){ // TODO what do we pass here?
//    CEFAuditRecord auditRecord = new CEFAuditRecord();
//    auditRecord.setCredhubServerVersion(this.credhubVersion);
//
//    securityEventsLogger.info(auditRecord);
  }
}
