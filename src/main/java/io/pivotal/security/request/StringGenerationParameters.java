package io.pivotal.security.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.generator.PassayStringCredentialGenerator;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

@JsonInclude(NON_DEFAULT)
public class StringGenerationParameters {

  // Value Parameters
  @JsonProperty(access = Access.WRITE_ONLY)
  private Integer length;

  private boolean excludeLower;
  private boolean excludeNumber;
  private boolean excludeUpper;
  private boolean includeSpecial;

  public int getLength() {
    return length == null ? PassayStringCredentialGenerator.DEFAULT_LENGTH : length;
  }

  public StringGenerationParameters setLength(int length) {
    this.length = length;
    return this;
  }

  public boolean isIncludeSpecial() {
    return includeSpecial;
  }

  public StringGenerationParameters setIncludeSpecial(boolean includeSpecial) {
    this.includeSpecial = includeSpecial;
    return this;
  }

  public boolean isExcludeNumber() {
    return excludeNumber;
  }

  public StringGenerationParameters setExcludeNumber(boolean excludeNumber) {
    this.excludeNumber = excludeNumber;
    return this;
  }

  public boolean isExcludeUpper() {
    return excludeUpper;
  }

  public StringGenerationParameters setExcludeUpper(boolean excludeUpper) {
    this.excludeUpper = excludeUpper;
    return this;
  }

  public boolean isExcludeLower() {
    return excludeLower;
  }

  public StringGenerationParameters setExcludeLower(boolean excludeLower) {
    this.excludeLower = excludeLower;
    return this;
  }

  @JsonIgnore
  public boolean isValid() {
    return !(!includeSpecial
        && excludeNumber
        && excludeUpper
        && excludeLower
      );
  }

  public void validate() {
    if (!isValid()) {
      throw new ParameterizedValidationException("error.excludes_all_charsets");
    }
  }
}
