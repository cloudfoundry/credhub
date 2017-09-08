package io.pivotal.security.view;

import org.codehaus.jackson.annotate.JsonAutoDetect;

import java.util.List;

@JsonAutoDetect
public class BulkRegenerateResults {
  private List<String> regeneratedCredentials;

  public BulkRegenerateResults() {
  }

  public List<String> getRegeneratedCredentials() {
    return regeneratedCredentials;
  }

  public void setRegeneratedCredentials(List<String> regeneratedCredentials) {
    this.regeneratedCredentials = regeneratedCredentials;
  }
}
