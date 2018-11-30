package org.cloudfoundry.credhub.config;

import java.security.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@Configuration
public class BouncyCastleProviderConfiguration {
  @Bean
  public BouncyCastleProvider bouncyCastleProvider() {
    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    Security.addProvider(bouncyCastleProvider);
    return bouncyCastleProvider;
  }

  @Bean
  public JcaContentSignerBuilder jcaContentSignerBuilder(BouncyCastleProvider jceProvider) {
    return new JcaContentSignerBuilder("SHA256withRSA").setProvider(jceProvider);
  }

  @Bean
  public JcaX509CertificateConverter jcaX509CertificateConverter(BouncyCastleProvider jceProvider) {
    return new JcaX509CertificateConverter().setProvider(jceProvider);
  }
}
