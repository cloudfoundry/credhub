package io.pivotal.security.request;

import org.hibernate.validator.constraints.NotEmpty;

import javax.validation.constraints.Pattern;

import static io.pivotal.security.request.BaseCredentialRequest.STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES;

public class CredentialRegenerateRequest {

  @NotEmpty(message = "error.missing_name")
  @Pattern(regexp = STARTS_WITH_SLASH_AND_AT_LEAST_ONE_NONSLASH_AND_HAS_NO_DOUBLE_SLASHES,
      message = "error.invalid_name_has_slash")
  private String name;
  private boolean regenerate;

  public String getName() {
    return name;
  }

  public CredentialRegenerateRequest setName(String name) {
    this.name = name;
    return this;
  }

  public void validate() {
    // Fill me out when switching to using this object.
  }

  public CredentialRegenerateRequest setRegenerate(boolean regenerate) {
    this.regenerate = regenerate;
    return this;
  }
}
