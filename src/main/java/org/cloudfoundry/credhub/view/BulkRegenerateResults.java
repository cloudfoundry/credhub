package org.cloudfoundry.credhub.view;

import java.util.Set;

import org.codehaus.jackson.annotate.JsonAutoDetect;

@JsonAutoDetect
public class BulkRegenerateResults {
  private Set<String> regeneratedCredentials;

  public BulkRegenerateResults() {
  }

  public Set<String> getRegeneratedCredentials() {
    return regeneratedCredentials;
  }

  public void setRegeneratedCredentials(Set<String> regeneratedCredentials) {
    this.regeneratedCredentials = regeneratedCredentials;
  }
}
