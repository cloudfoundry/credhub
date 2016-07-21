package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;

@Configuration
public class ResourceServerTokenServicesConfig {

  @Autowired
  AuthServerProperties authServerProperties;

  @Bean
  ResourceServerTokenServices tokenServices() {
    final RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
    remoteTokenServices.setClientId(authServerProperties.getClient());
    remoteTokenServices.setClientSecret(authServerProperties.getClientSecret());
    remoteTokenServices.setCheckTokenEndpointUrl(authServerProperties.getUrl() + "/check_token");
    return remoteTokenServices;
  }
}
