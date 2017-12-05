package org.cloudfoundry.credhub.config;

import org.cloudfoundry.credhub.service.EncryptionService;
import org.passay.PasswordGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PassayConfiguration {

  @Bean
  public PasswordGenerator passwordGenerator(EncryptionService encryptionService) {
    return new PasswordGenerator(encryptionService.getSecureRandom());
  }

}
