package io.pivotal.security.config;


import io.pivotal.security.util.ResourceReader;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class VersionProvider {
  private final String version;

  public VersionProvider(ResourceReader resources) throws IOException {
    version = resources.readFileToString("version").trim();
  }

  public String currentVersion() {
    return version;
  }
}
