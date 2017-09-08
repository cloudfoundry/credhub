package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import javax.validation.constraints.NotNull;

@JsonAutoDetect
@SuppressWarnings("unused")
public class BulkRegenerateRequest {

  @NotNull
  private String signedBy;

  public BulkRegenerateRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public BulkRegenerateRequest(String signedBy) {
    this.signedBy = signedBy;
  }

  public String getSignedBy() {
    return signedBy;
  }

  public void setSignedBy(String signedBy) {
    this.signedBy = signedBy;
  }
}
