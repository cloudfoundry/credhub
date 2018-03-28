package org.cloudfoundry.credhub.service;

import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.config.VersionProvider;
import org.springframework.beans.factory.annotation.Autowired;

public class AuditEventLogService {

  private String credhubVersion;
  private Logger securityEventsLogger;

  @Autowired
  public AuditEventLogService(VersionProvider versionProvider, Logger securityEventsLogger){
    this.credhubVersion = versionProvider.currentVersion();
    this.securityEventsLogger = securityEventsLogger;
  }
}
