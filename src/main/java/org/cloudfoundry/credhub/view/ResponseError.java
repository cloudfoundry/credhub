package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect
public class ResponseError {

  private final String error;

  public ResponseError(final String error) {
    super();
    this.error = error;
  }

  public String getError() {
    return error;
  }
}
