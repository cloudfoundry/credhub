package io.pivotal.security;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.Option;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CredentialManagerApp {

  public static void main(String[] args) {
    SpringApplication.run(CredentialManagerApp.class, args);
  }

  @Bean
  Configuration getConfiguration() {
    return Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS);
  }
}
