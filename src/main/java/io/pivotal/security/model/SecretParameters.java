package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SecretParameters {

  private int length;

  @JsonProperty("exclude_upper")
  private boolean excludeUpper;

  @JsonProperty("exclude_lower")
  private boolean excludeLower;

  @JsonProperty("exclude_special")
  private boolean excludeSpecial;

  public int getLength() {
    return length;
  }

  public void setLength(int length) {
    this.length = length;
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

  public boolean isExcludeSpecial() {
    return excludeSpecial;
  }

  public void setExcludeSpecial(boolean excludeSpecial) {
    this.excludeSpecial = excludeSpecial;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    SecretParameters that = (SecretParameters) o;

    if (length != that.length) return false;
    if (excludeUpper != that.excludeUpper) return false;
    if (excludeLower != that.excludeLower) return false;
    return excludeSpecial == that.excludeSpecial;
  }

  @Override
  public int hashCode() {
    int result = length;
    result = 31 * result + (excludeUpper ? 1 : 0);
    result = 31 * result + (excludeLower ? 1 : 0);
    result = 31 * result + (excludeSpecial ? 1 : 0);
    return result;
  }

}
