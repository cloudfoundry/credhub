package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.pivotal.security.entity.NamedSecret;

import static com.google.common.collect.Lists.newArrayList;

import java.util.ArrayList;
import java.util.List;

public class DataResponse {
  private List<Secret> data;

  public DataResponse(List<Secret> data) {
    this.data = data;
  }

  public static DataResponse fromEntity(List<NamedSecret> secrets) {
    ArrayList<Secret> secretsList = newArrayList();
    for(NamedSecret s: secrets) {
      secretsList.add(Secret.fromEntity(s));
    }
    return new DataResponse(secretsList);
  }

  @JsonProperty
  public List<Secret> getData() {
    return data;
  }
}
