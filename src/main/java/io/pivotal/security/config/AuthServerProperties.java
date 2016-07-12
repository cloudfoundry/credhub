package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import java.util.Collections;

@ConfigurationProperties("auth-server")
public class AuthServerProperties {

  @Autowired
  ConfigurableEnvironment environment;

  @NotNull(message = "The auth-server.url configuration property is required.")
  private String url;

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  @PostConstruct
  public void init() {
    MapPropertySource propertySource = new MapPropertySource("auth-server", Collections.singletonMap("info.auth-server.url", getUrl()));
    environment.getPropertySources().addFirst(propertySource);
  }
}
