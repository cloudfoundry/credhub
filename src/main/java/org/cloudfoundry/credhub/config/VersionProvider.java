package org.cloudfoundry.credhub.config;


import java.io.IOException;

import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.util.ResourceReader;

@Component
public class VersionProvider {
  private String version;

  VersionProvider(ResourceReader resources) {
    try {
      version = resources.readFileToString("version").trim();
    } catch (IOException | IllegalArgumentException e) {
      version = "0.0.0";
    }
  }

  public String currentVersion() {
    return version;
  }
}
