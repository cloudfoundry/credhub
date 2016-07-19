package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import javax.annotation.PostConstruct;
import javax.validation.constraints.NotNull;
import java.util.Collections;

@ConfigurationProperties("data-storage")
public class DataStorageProperties {
  @Autowired
  ConfigurableEnvironment environment;

  @NotNull(message = "The data-storage.type configuration property is required.")
  private String type;

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  @PostConstruct
  public void init() {
    if(!"in-memory".equals(type)) {
      throw new RuntimeException("'in-memory' is the only legal storage type");
    }
    MapPropertySource propertySource = new MapPropertySource("data-storage", Collections.singletonMap("data-storage.type", getType()));
    environment.getPropertySources().addFirst(propertySource);
  }
}
