package org.cloudfoundry.credhub.requests;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.ErrorMessages;

@JsonAutoDetect
@SuppressWarnings("unused")
public class BulkRegenerateRequest {

  @JsonProperty("signed_by")
  @NotNull(message = ErrorMessages.MISSING_SIGNED_BY)
  private String signedBy;

  public BulkRegenerateRequest() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public BulkRegenerateRequest(final String signedBy) {
    super();
    this.signedBy = signedBy;
  }

  public String getSignedBy() {
    return signedBy;
  }

  public void setSignedBy(final String signedBy) {
    this.signedBy = StringUtils.prependIfMissing(signedBy, "/");
  }
}
