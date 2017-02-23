package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.domain.NamedSecret;

import java.util.ArrayList;
import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

public class DataResponse {
  private List<SecretView> data;

  public DataResponse(List<SecretView> data) {
    this.data = data;
  }

  public static DataResponse fromEntity(List<NamedSecret> models) {
    ArrayList<SecretView> views = newArrayList();
    for(NamedSecret model: models) {
      views.add(SecretView.fromEntity((model)));
    }
    return new DataResponse(views);
  }

  @JsonProperty
  public List<SecretView> getData() {
    return data;
  }
}
