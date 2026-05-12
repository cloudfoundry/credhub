package org.cloudfoundry.credhub.config;

import java.security.SecureRandom;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.cloudfoundry.credhub.services.RandomNumberGenerator;

@Configuration
public class PassayConfiguration {

  @Bean
  public SecureRandom secureRandom(final RandomNumberGenerator randomNumberGenerator) {
    return randomNumberGenerator.getSecureRandom();
  }

}
