package org.cloudfoundry.credhub.request;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.StringUtils;

@JsonAutoDetect
@SuppressWarnings("unused")
public class BulkRegenerateRequest {

  @JsonProperty("signed_by")
  @NotNull(message = "error.missing_signed_by")
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
    this.signedBy = StringUtils.prependIfMissing(signedBy, "/");
  }
}
