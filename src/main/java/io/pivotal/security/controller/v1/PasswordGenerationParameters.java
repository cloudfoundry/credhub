package io.pivotal.security.controller.v1;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

@JsonInclude(NON_DEFAULT)
public class PasswordGenerationParameters implements RequestParameters {
  // Value Parameters
  @JsonIgnore
  private int length;

  @JsonProperty(value = "exclude_lower", index = 0)
  private boolean excludeLower;

  @JsonProperty(value = "exclude_number", index = 1)
  private boolean excludeNumber;

  @JsonProperty(value = "exclude_special", index = 2)
  private boolean excludeSpecial;

  @JsonProperty(value = "exclude_upper", index = 3)
  private boolean excludeUpper;

  @JsonProperty(value = "only_hex", index = 4)
  private boolean onlyHex;

  public int getLength() {
    return length;
  }

  public PasswordGenerationParameters setLength(int length) {
    this.length = length;
    return this;
  }

  public boolean isExcludeSpecial() {
    return excludeSpecial;
  }

  public PasswordGenerationParameters setExcludeSpecial(boolean excludeSpecial) {
    this.excludeSpecial = excludeSpecial;
    return this;
  }

  public boolean isExcludeNumber() {
    return excludeNumber;
  }

  public PasswordGenerationParameters setExcludeNumber(boolean excludeNumber) {
    this.excludeNumber = excludeNumber;
    return this;
  }

  public boolean isExcludeUpper() {
    return excludeUpper;
  }

  public PasswordGenerationParameters setExcludeUpper(boolean excludeUpper) {
    this.excludeUpper = excludeUpper;
    return this;
  }

  public boolean isExcludeLower() {
    return excludeLower;
  }

  public PasswordGenerationParameters setExcludeLower(boolean excludeLower) {
    this.excludeLower = excludeLower;
    return this;
  }

  public boolean isOnlyHex() {
    return onlyHex;
  }

  public PasswordGenerationParameters setOnlyHex(boolean onlyHex) {
    this.onlyHex = onlyHex;

    return this;
  }

  @JsonIgnore
  public boolean isValid() {
    return !(excludeSpecial
        && excludeNumber
        && excludeUpper
        && excludeLower
        && !onlyHex
    );
  }
}
