package org.cloudfoundry.credhub.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

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
