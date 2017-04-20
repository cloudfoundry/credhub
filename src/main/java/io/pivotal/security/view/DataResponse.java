package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.Credential;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

public class DataResponse {

  private List<CredentialView> data;

  public DataResponse(List<CredentialView> data) {
    this.data = data;
  }

  public static DataResponse fromEntity(List<Credential> models) {
    ArrayList<CredentialView> views = newArrayList();
    for (Credential model : models) {
      views.add(CredentialView.fromEntity((model)));
    }
    return new DataResponse(views);
  }

  @JsonProperty
  public List<CredentialView> getData() {
    return data;
  }
}
