package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class FindCredentialResults {

  private List<CredentialView> credentials;

  @SuppressWarnings("rawtypes")
  FindCredentialResults(List<CredentialView> credentials) {
    this.credentials = credentials;
  }

  public static FindCredentialResults fromCredentials(List<CredentialView> credentials) {
    return new FindCredentialResults(credentials);
  }

  @JsonProperty
  public List<CredentialView> getCredentials() {
    return credentials;
  }

}
