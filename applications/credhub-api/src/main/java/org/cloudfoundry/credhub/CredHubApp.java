package org.cloudfoundry.credhub;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.cloudfoundry.credhub.config.CurrentTimeProviderConfig;

@SpringBootApplication
@EnableJpaAuditing(dateTimeProviderRef = CurrentTimeProviderConfig.CURRENT_TIME_PROVIDER)
public class CredHubApp {

  public static void main(final String[] args) {
    SpringApplication.run(CredHubApp.class, args);
  }

  @Bean
  public WebServerFactoryCustomizer servletContainerCustomizer() {
    return (factory) -> ((TomcatServletWebServerFactory) factory)
      .addConnectorCustomizers((connector) -> ((AbstractHttp11Protocol<?>) connector.getProtocolHandler())
        .setUseServerCipherSuitesOrder(true));
  }
}
