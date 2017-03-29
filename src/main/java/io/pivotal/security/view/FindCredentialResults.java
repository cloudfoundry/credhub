package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class FindCredentialResults {

  private List<SecretView> credentials;

  @SuppressWarnings("rawtypes")
  FindCredentialResults(List<SecretView> credentials) {
    this.credentials = credentials;
  }

  public static FindCredentialResults fromSecrets(List<SecretView> secrets) {
    return new FindCredentialResults(secrets);
  }

  @JsonProperty
  public List<SecretView> getCredentials() {
    return credentials;
  }

}
