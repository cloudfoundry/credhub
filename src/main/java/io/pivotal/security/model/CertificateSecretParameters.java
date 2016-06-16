package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.util.StringUtils;

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

  public void setCommonName(String commonName) {
    this.commonName = commonName;
  }

  public void setOrganization(String organization) {
    this.organization = organization;
  }

  public void setOrganizationUnit(String organizationUnit) {
    this.organizationUnit = organizationUnit;
  }

  public void setLocality(String locality) {
    this.locality = locality;
  }

  public void setState(String state) {
    this.state = state;
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

  public boolean isValid() {
    return !StringUtils.isEmpty(organization)
        && !StringUtils.isEmpty(state)
        && !StringUtils.isEmpty(country);
  }
  private boolean areStringsEqual(String s1, String s2) {
    return s1 != null ? s1.equals(s2) : s2 == null;
  }


  public String getDNString() {
    final StringBuilder strb = new StringBuilder();

    strb.append("CN=").append(commonName)
        .append(",O=").append(organization)
        .append(",OU=").append(organizationUnit)
        .append(",L=").append(locality)
        .append(",ST=").append(state)
        .append(",C=").append(country);
    return strb.toString();
  }
}