package io.pivotal.security.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

  @JsonProperty("alternative_name")
  private String[] alternateNames = new String[0];

  @JsonProperty("key_length")
  private int keyLength = 2048;

  public CertificateSecretParameters setCommonName(String commonName) {
    this.commonName = commonName;
    return this;
  }

  public CertificateSecretParameters setOrganization(String organization) {
    this.organization = organization;
    return this;
  }

  public CertificateSecretParameters setOrganizationUnit(String organizationUnit) {
    this.organizationUnit = organizationUnit;
    return this;
  }

  public CertificateSecretParameters setLocality(String locality) {
    this.locality = locality;
    return this;
  }

  public CertificateSecretParameters setState(String state) {
    this.state = state;
    return this;
  }

  public CertificateSecretParameters setCountry(String country) {
    this.country = country;
    return this;
  }

  @Override
  public boolean equals(Object o) {
    return EqualsBuilder.reflectionEquals(this, o);
  }

  @Override
  public int hashCode() {
    return HashCodeBuilder.reflectionHashCode(this);
  }

  public void validate() throws ValidationException {
    if (StringUtils.isEmpty(organization)
        || StringUtils.isEmpty(state)
        || StringUtils.isEmpty(country)) {
      throw new ValidationException("error.missing_certificate_parameters");
    }
  }

  public String getDNString() {
    final StringBuilder strb = new StringBuilder();

    strb.append("O=").append(organization)
        .append(",ST=").append(state)
        .append(",C=").append(country);

    if (!StringUtils.isEmpty(commonName)) {
      strb.append(",CN=").append(commonName);
    }
    if (!StringUtils.isEmpty(organizationUnit)) {
      strb.append(",OU=").append(organizationUnit);
    }
    if (!StringUtils.isEmpty(locality)) {
      strb.append(",L=").append(locality);
    }
    return strb.toString();
  }

  public void addAlternateName(String alternateName) {
    List<String> tmp = new ArrayList<>(Arrays.asList(alternateNames));
    tmp.add(alternateName);
    alternateNames = tmp.toArray(new String[tmp.size()]);
  }

  public void addAlternateNames(String[] alternateNames) {
    for (String a : alternateNames) {
      addAlternateName(a);
    }
  }

  public List<String> getAlternateNames() {
    return Arrays.asList(alternateNames);
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }

  public int getKeyLength() {
    return keyLength;
  }
}