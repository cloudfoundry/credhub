package org.cloudfoundry.credhub.views;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.credhub.domain.CredentialVersion;

import static com.google.common.collect.Lists.newArrayList;

public class DataResponse {

  private final List<CredentialView> data;

  public DataResponse(final List<CredentialView> data) {
    super();
    this.data = data;
  }

  public static DataResponse fromEntity(final List<CredentialVersion> models) {
    final List<CredentialView> views = newArrayList();
    for (final CredentialVersion model : models) {
      if (model != null) {
        views.add(CredentialView.fromEntity(model));
      }
    }
    return new DataResponse(views);
  }

  @JsonProperty
  public List<CredentialView> getData() {
    return data;
  }
}
