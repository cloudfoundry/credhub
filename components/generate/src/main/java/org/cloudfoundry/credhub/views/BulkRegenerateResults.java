package org.cloudfoundry.credhub.views;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
public class BulkRegenerateResults {
  private Set<String> regeneratedCredentials;

  public Set<String> getRegeneratedCredentials() {
    return regeneratedCredentials;
  }

  public void setRegeneratedCredentials(final Set<String> regeneratedCredentials) {
    this.regeneratedCredentials = regeneratedCredentials;
  }
}
