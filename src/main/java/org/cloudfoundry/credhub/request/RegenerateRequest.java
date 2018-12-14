package org.cloudfoundry.credhub.request;

import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import org.apache.commons.lang3.StringUtils;

@JsonAutoDetect
@SuppressWarnings("unused")
public class RegenerateRequest {

  @NotNull(message = "error.missing_name")
  private String name;

  public RegenerateRequest() {
    super();
    /* this needs to be there for jackson to be happy */
  }

  public RegenerateRequest(final String name) {
    super();
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public void setName(final String name) {
    this.name = StringUtils.prependIfMissing(name, "/");
  }
}
