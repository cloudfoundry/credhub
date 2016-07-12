package io.pivotal.security.view;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class Secret<ET, T> extends BaseView<ET, T> {
  @JsonProperty
  public abstract String getType();
}