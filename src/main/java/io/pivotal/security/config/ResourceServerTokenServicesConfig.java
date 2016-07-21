package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;

@Configuration
public class ResourceServerTokenServicesConfig {

  @Autowired
  AuthServerProperties authServerProperties;

  @Autowired
  RestTemplate remoteTokenServicesRestTemplate;

  @Bean
  ResourceServerTokenServices tokenServices() {
    remoteTokenServicesRestTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
      @Override
      // Ignore 400
      public void handleError(ClientHttpResponse response) throws IOException {
        if (response.getRawStatusCode() != 400) {
          super.handleError(response);
        }
      }
    });

    final RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
    remoteTokenServices.setClientId(authServerProperties.getClient());
    remoteTokenServices.setClientSecret(authServerProperties.getClientSecret());
    remoteTokenServices.setCheckTokenEndpointUrl("https://localhost:8443/check_token");
    remoteTokenServices.setRestTemplate(remoteTokenServicesRestTemplate);
    return remoteTokenServices;
  }
}
