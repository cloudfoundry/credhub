package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class FindCredentialResults {

  private List<CredentialView> credentials;

  @SuppressWarnings("rawtypes")
  FindCredentialResults(List<CredentialView> credentials) {
    this.credentials = credentials;
  }

  public static FindCredentialResults fromSecrets(List<CredentialView> secrets) {
    return new FindCredentialResults(secrets);
  }

  @JsonProperty
  public List<CredentialView> getCredentials() {
    return credentials;
  }

}
