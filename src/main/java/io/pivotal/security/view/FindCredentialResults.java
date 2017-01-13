package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedSecret;

import static com.google.common.collect.Lists.newArrayList;

import java.util.List;

public class FindCredentialResults {
  private List<Credential> credentials;

  @SuppressWarnings("rawtypes")
  FindCredentialResults(List<Credential> credentials) {
    this.credentials = credentials;
  }

  public static FindCredentialResults fromEntity(List<NamedSecret> secrets) {
    List<Credential> credentials = newArrayList();
    for(NamedSecret s: secrets) {
      credentials.add(new Credential(s.getName(), s.getVersionCreatedAt()));
    }
    return new FindCredentialResults(credentials);
  }

  @JsonProperty
  public List<Credential> getCredentials() {
    return credentials;
  }

}
