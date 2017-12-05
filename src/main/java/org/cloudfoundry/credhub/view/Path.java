package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonProperty;

class Path {

  private String path;

  public Path(String path) {
    this.path = path;
  }

  @JsonProperty
  public String getPath() {
    return path;
  }
}
