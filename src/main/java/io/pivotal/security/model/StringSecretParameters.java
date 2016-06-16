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

  public boolean isValid() {
    return !(excludeSpecial
        && excludeNumber
        && excludeUpper
        && excludeLower);
  }
}