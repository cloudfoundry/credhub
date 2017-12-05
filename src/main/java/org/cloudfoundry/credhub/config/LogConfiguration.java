package org.cloudfoundry.credhub.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class LogConfiguration {

  @Bean
  public Logger securityEventsLogger() {
    return LogManager.getLogger("CREDHUB_SECURITY_EVENTS");
  }
}
