package io.pivotal.security.config;

import io.pivotal.security.service.EncryptionService;
import org.passay.PasswordGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;

@Configuration
public class PassayConfiguration {

  @Bean
  public PasswordGenerator passwordGenerator(EncryptionService encryptionService) {
    return new PasswordGenerator(encryptionService.getSecureRandom());
  }

}
