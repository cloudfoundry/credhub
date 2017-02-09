package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static com.google.common.collect.Lists.newArrayList;

public class DataResponse<M, V> {
  private List<V> data;

  public DataResponse(List<V> data) {
    this.data = data;
  }

  public static <M, V> DataResponse fromEntity(List<M> models, Function<M, V> make) {
    ArrayList<V> views = newArrayList();
    for(M model: models) {
      views.add(make.apply(model));
    }
    return new DataResponse<M, V>(views);
  }

  @JsonProperty
  public List<V> getData() {
    return data;
  }
}
