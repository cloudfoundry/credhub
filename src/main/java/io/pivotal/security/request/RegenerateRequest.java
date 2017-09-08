package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import javax.validation.constraints.NotNull;

@JsonAutoDetect
@SuppressWarnings("unused")
public class RegenerateRequest {

  @NotNull
  private String name;

  public RegenerateRequest() {
        /* this needs to be there for jackson to be happy */
  }

  public RegenerateRequest(String name) {
    this.name = name;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }
}
