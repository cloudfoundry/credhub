package org.cloudfoundry.credhub.config;

import java.security.Security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

@Configuration
public class BouncyCastleProviderConfiguration {
  @Bean
  public BouncyCastleFipsProvider bouncyCastleProvider() {
    final BouncyCastleFipsProvider bouncyCastleProvider = new BouncyCastleFipsProvider();
    Security.addProvider(bouncyCastleProvider);
    return bouncyCastleProvider;
  }

  @Bean
  public JcaContentSignerBuilder jcaContentSignerBuilder(final BouncyCastleFipsProvider jceProvider) {
    return new JcaContentSignerBuilder("SHA256withRSA").setProvider(jceProvider);
  }

  @Bean
  public JcaX509CertificateConverter jcaX509CertificateConverter(final BouncyCastleFipsProvider jceProvider) {
    return new JcaX509CertificateConverter().setProvider(jceProvider);
  }
}
