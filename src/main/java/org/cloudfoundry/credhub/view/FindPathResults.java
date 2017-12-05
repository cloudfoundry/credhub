package org.cloudfoundry.credhub.view;

import static com.google.common.collect.Lists.newArrayList;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class FindPathResults {

  private List<Path> paths;

  @SuppressWarnings("rawtypes")
  FindPathResults(List<Path> paths) {
    this.paths = paths;
  }

  public static FindPathResults fromEntity(List<String> pathStrings) {
    List<Path> paths = newArrayList();
    for (String p : pathStrings) {
      paths.add(new Path(p));
    }
    return new FindPathResults(paths);
  }

  @JsonProperty
  public List<Path> getPaths() {
    return paths;
  }
}
