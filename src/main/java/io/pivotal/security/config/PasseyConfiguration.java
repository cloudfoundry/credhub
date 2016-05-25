package io.pivotal.security.config;

import org.passay.PasswordGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class PasseyConfiguration {

  @Bean
  public PasswordGenerator passwordGenerator() {
    return new PasswordGenerator();
  }

}
