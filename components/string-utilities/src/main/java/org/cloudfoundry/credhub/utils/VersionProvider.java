package org.cloudfoundry.credhub.utils;

import java.io.IOException;

import org.springframework.stereotype.Component;

@Component
public class VersionProvider {
  private String version;

  public VersionProvider(final ResourceReader resources) {
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
