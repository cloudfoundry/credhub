package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties("auth-server")
public class AuthServerProperties {
  private final ConfigurableEnvironment environment;

  @Autowired
  AuthServerProperties(ConfigurableEnvironment environment) {
    this.environment = environment;
  }

  @NotNull(message = "The auth-server.url configuration property is required.")
  private String url;

  private final String client = "credhub_cli";
  private final String clientSecret = "";

  public String getUrl() {
    return url;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public String getClient() {
    return client;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  @PostConstruct
  public void init() {
    Map<String, Object> map = new HashMap<>();
    map.put("info.auth-server.url", getUrl());
    MapPropertySource propertySource = new MapPropertySource("auth-server", map);
    environment.getPropertySources().addFirst(propertySource);
  }
}
