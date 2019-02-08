package org.cloudfoundry.credhub.views;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FindCredentialResults {

  private final List<FindCredentialResult> credentials;

  @SuppressWarnings("rawtypes")
  public FindCredentialResults(final List<FindCredentialResult> credentials) {
    super();
    this.credentials = credentials;
  }

  @JsonProperty
  public List<FindCredentialResult> getCredentials() {
    return credentials;
  }

}
