package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Collections;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

@ConfigurationProperties("data-storage")
public class DataStorageProperties {
  @Autowired
  ConfigurableEnvironment environment;

  @NotNull(message = "The data-storage.type configuration property is required.")
  @Pattern(regexp = "in-memory", message = "The data-storage.type configuration property must be \"in-memory\".")
  private String type;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  @PostConstruct
  public void init() {
    MapPropertySource propertySource = new MapPropertySource("data-storage", Collections.singletonMap("data-storage.type", getType()));
    environment.getPropertySources().addFirst(propertySource);
  }
}
