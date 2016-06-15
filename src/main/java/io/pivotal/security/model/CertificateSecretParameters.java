package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateSecretParameters {
  // Required Certificate Parameters
  @JsonProperty("organization")
  private String organization;

  @JsonProperty("state")
  private String state;

  @JsonProperty("country")
  private String country;

  // Optional Certificate Parameters
  @JsonProperty("common_name")
  private String commonName;

  @JsonProperty("organization_unit")
  private String organizationUnit;

  @JsonProperty("locality")
  private String locality;

  public String getCommonName() {
    return commonName;
  }

  public void setCommonName(String commonName) {
    this.commonName = commonName;
  }

  public String getOrganization() {
    return organization;
  }

  public void setOrganization(String organization) {
    this.organization = organization;
  }

  public String getOrganizationUnit() {
    return organizationUnit;
  }

  public void setOrganizationUnit(String organizationUnit) {
    this.organizationUnit = organizationUnit;
  }

  public String getLocality() {
    return locality;
  }

  public void setLocality(String locality) {
    this.locality = locality;
  }

  public String getState() {
    return state;
  }

  public void setState(String state) {
    this.state = state;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    CertificateSecretParameters that = (CertificateSecretParameters) o;

    return areStringsEqual(commonName, that.commonName)
        && areStringsEqual(organization, that.organization)
        && areStringsEqual(organizationUnit, that.organizationUnit)
        && areStringsEqual(locality, that.locality)
        && areStringsEqual(state, that.state)
        && areStringsEqual(country, that.country);
  }

  private boolean areStringsEqual(String s1, String s2) {
    return s1 != null ? s1.equals(s2) : s2 == null;
  }
}