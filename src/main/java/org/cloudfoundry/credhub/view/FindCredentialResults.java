package org.cloudfoundry.credhub.view;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FindCredentialResults {

  private List<FindCredentialResult> credentials;

  @SuppressWarnings("rawtypes")
  public FindCredentialResults(List<FindCredentialResult> credentials) {
    this.credentials = credentials;
  }

  @JsonProperty
  public List<FindCredentialResult> getCredentials() {
    return credentials;
  }

}
