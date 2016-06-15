package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

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

  public void setLength(int length) {
    this.length = length;
  }

  public boolean isExcludeSpecial() {
    return excludeSpecial;
  }

  public void setExcludeSpecial(boolean excludeSpecial) {
    this.excludeSpecial = excludeSpecial;
  }

  public boolean isExcludeNumber() {
    return excludeNumber;
  }

  public void setExcludeNumber(boolean excludeNumber) {
    this.excludeNumber = excludeNumber;
  }

  public boolean isExcludeUpper() {
    return excludeUpper;
  }

  public void setExcludeUpper(boolean excludeUpper) {
    this.excludeUpper = excludeUpper;
  }

  public boolean isExcludeLower() {
    return excludeLower;
  }

  public void setExcludeLower(boolean excludeLower) {
    this.excludeLower = excludeLower;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    StringSecretParameters that = (StringSecretParameters) o;

    if (length != that.length) {
      return false;
    }
    if (excludeSpecial != that.excludeSpecial) {
      return false;
    }
    if (excludeNumber != that.excludeNumber) {
      return false;
    }
    if (excludeUpper != that.excludeUpper) {
      return false;
    }
    return excludeLower == that.excludeLower;
  }

  @Override
  public int hashCode() {
    int result = length;
    result = 31 * result + (excludeSpecial ? 1 : 0);
    result = 31 * result + (excludeNumber ? 1 : 0);
    result = 31 * result + (excludeUpper ? 1 : 0);
    result = 31 * result + (excludeLower ? 1 : 0);
    return result;
  }
}