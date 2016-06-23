package io.pivotal.security.controller.v1;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class StringSecretParameters {
  // Value Parameters
  private int length;
  private boolean excludeSpecial;
  private boolean excludeNumber;
  private boolean excludeUpper;
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

  public boolean isValid() {
    return !(excludeSpecial
        && excludeNumber
        && excludeUpper
        && excludeLower);
  }
}