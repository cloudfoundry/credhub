package io.pivotal.security.request;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import io.pivotal.security.controller.v1.RequestParameters;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.generator.PassayStringSecretGenerator;

@JsonInclude(NON_DEFAULT)
public class PasswordGenerationParameters implements RequestParameters {

  // Value Parameters
  @JsonProperty(access = Access.WRITE_ONLY)
  private Integer length;

  private boolean excludeLower;
  private boolean excludeNumber;
  private boolean excludeUpper;
  private boolean includeSpecial;
  private boolean onlyHex;

  public int getLength() {
    return length == null ? PassayStringSecretGenerator.DEFAULT_LENGTH : length;
  }

  public PasswordGenerationParameters setLength(int length) {
    this.length = length;
    return this;
  }

  public boolean isIncludeSpecial() {
    return includeSpecial;
  }

  public PasswordGenerationParameters setIncludeSpecial(boolean includeSpecial) {
    this.includeSpecial = includeSpecial;
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
    return !(!includeSpecial
        && excludeNumber
        && excludeUpper
        && excludeLower
        && !onlyHex
      );
  }

  public void validate() {
    if (!isValid()) {
      throw new ParameterizedValidationException("error.excludes_all_charsets");
    }
  }
}
