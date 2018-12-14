package org.cloudfoundry.credhub.config;


import java.io.IOException;

import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.util.ResourceReader;

@Component
public class VersionProvider {
  private String version;

  VersionProvider(final ResourceReader resources) {
    super();
    try {
      version = resources.readFileToString("version").trim();
    } catch (final IOException | IllegalArgumentException e) {
      version = "0.0.0";
    }
  }

  public String currentVersion() {
    return version;
  }
}
