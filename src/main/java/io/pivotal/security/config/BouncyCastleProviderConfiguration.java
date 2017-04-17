package io.pivotal.security.config;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BouncyCastleProviderConfiguration {
  @Bean
  public BouncyCastleProvider bouncyCastleProvider() {
    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    Security.addProvider(bouncyCastleProvider);
    return bouncyCastleProvider;
  }
}
