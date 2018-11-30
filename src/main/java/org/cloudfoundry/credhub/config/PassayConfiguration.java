package org.cloudfoundry.credhub.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.cloudfoundry.credhub.service.RandomNumberGenerator;
import org.passay.PasswordGenerator;

@Configuration
public class PassayConfiguration {

  @Bean
  public PasswordGenerator passwordGenerator(RandomNumberGenerator randomNumberGenerator) {
    return new PasswordGenerator(randomNumberGenerator.getSecureRandom());
  }

}
