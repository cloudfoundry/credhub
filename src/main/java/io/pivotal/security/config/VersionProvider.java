package io.pivotal.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
public class VersionProvider {
  private String version;

  @Autowired
  Environment environment;

  @PostConstruct
  private void init() {
    try {
      version = environment.getProperty("info.app.version");
    } catch (IllegalArgumentException e) {
      version = "dev";
    }
  }

  public String getVersion() {
    return version;
  }
}
