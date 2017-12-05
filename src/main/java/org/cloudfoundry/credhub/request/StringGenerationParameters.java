package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.generator.PassayStringCredentialGenerator;

import java.util.Objects;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

@JsonInclude(NON_DEFAULT)
public class StringGenerationParameters implements GenerationParameters{

  // Value Parameters
  @JsonProperty(access = Access.WRITE_ONLY)
  private Integer length = PassayStringCredentialGenerator.DEFAULT_LENGTH;

  private String username;

  private boolean excludeLower;
  private boolean excludeNumber;
  private boolean excludeUpper;
  private boolean includeSpecial;

  public int getLength() {
    return length;
  }

  public StringGenerationParameters setLength(int length) {
    this.length = length;
    return this;
  }

  public String getUsername() {
    return username;
  }

  public StringGenerationParameters setUsername(String username) {
    this.username = username;
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

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    StringGenerationParameters that = (StringGenerationParameters) o;
    return excludeLower == that.excludeLower &&
        excludeNumber == that.excludeNumber &&
        excludeUpper == that.excludeUpper &&
        includeSpecial == that.includeSpecial &&
        Objects.equals(length, that.length) &&
        Objects.equals(username, that.username);
  }

  @Override
  public int hashCode() {
    return Objects.hash(length, username, excludeLower, excludeNumber, excludeUpper, includeSpecial);
  }

  public boolean passwordOptionsEqual(StringGenerationParameters that) {
    return excludeLower == that.excludeLower &&
        excludeNumber == that.excludeNumber &&
        excludeUpper == that.excludeUpper &&
        includeSpecial == that.includeSpecial;
  }
}
