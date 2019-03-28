package org.cloudfoundry.credhub.requests;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonProperty.Access;
import org.cloudfoundry.credhub.ErrorMessages;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.cloudfoundry.credhub.generators.PassayStringCredentialGenerator;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;

@JsonInclude(NON_DEFAULT)
public class StringGenerationParameters extends GenerationParameters {

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

  public void setLength(final int length) {
    this.length = length;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(final String username) {
    this.username = username;
  }

  public boolean isIncludeSpecial() {
    return includeSpecial;
  }

  public void setIncludeSpecial(final boolean includeSpecial) {
    this.includeSpecial = includeSpecial;
  }

  public boolean isExcludeNumber() {
    return excludeNumber;
  }

  public void setExcludeNumber(final boolean excludeNumber) {
    this.excludeNumber = excludeNumber;
  }

  public boolean isExcludeUpper() {
    return excludeUpper;
  }

  public void setExcludeUpper(final boolean excludeUpper) {
    this.excludeUpper = excludeUpper;
  }

  public boolean isExcludeLower() {
    return excludeLower;
  }

  public void setExcludeLower(final boolean excludeLower) {
    this.excludeLower = excludeLower;
  }

  @JsonIgnore
  public boolean isValid() {
    return !(!includeSpecial
      && excludeNumber
      && excludeUpper
      && excludeLower
    );
  }

  @Override
  public void validate() {
    if (!isValid()) {
      throw new ParameterizedValidationException(ErrorMessages.EXCLUDES_ALL_CHARSETS);
    }
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }

    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final StringGenerationParameters that = (StringGenerationParameters) o;
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
}
