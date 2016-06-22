package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class StringSecretParameters {

  private int length;

  // Value Parameters
  @JsonProperty("exclude_special")
  private boolean excludeSpecial;

  @JsonProperty("exclude_number")
  private boolean excludeNumber;

  @JsonProperty("exclude_upper")
  private boolean excludeUpper;

  @JsonProperty("exclude_lower")
  private boolean excludeLower;

  public int getLength() {
    return length;
  }

  public StringSecretParameters setLength(int length) {
    this.length = length;
    return this;
  }

  public boolean isExcludeSpecial() {
    return excludeSpecial;
  }

  public StringSecretParameters setExcludeSpecial(boolean excludeSpecial) {
    this.excludeSpecial = excludeSpecial;
    return this;
  }

  public boolean isExcludeNumber() {
    return excludeNumber;
  }

  public StringSecretParameters setExcludeNumber(boolean excludeNumber) {
    this.excludeNumber = excludeNumber;
    return this;
  }

  public boolean isExcludeUpper() {
    return excludeUpper;
  }

  public StringSecretParameters setExcludeUpper(boolean excludeUpper) {
    this.excludeUpper = excludeUpper;
    return this;
  }

  public boolean isExcludeLower() {
    return excludeLower;
  }

  public StringSecretParameters setExcludeLower(boolean excludeLower) {
    this.excludeLower = excludeLower;
    return this;
  }

  @Override
  public boolean equals(Object o) {
    return EqualsBuilder.reflectionEquals(this, o);
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  public boolean isValid() {
    return !(excludeSpecial
        && excludeNumber
        && excludeUpper
        && excludeLower);
  }
}