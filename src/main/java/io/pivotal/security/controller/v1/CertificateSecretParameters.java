package io.pivotal.security.controller.v1;

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
  private String[] alternativeNames = new String[0];

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

    switch (keyLength) {
      case 2048:
      case 3072:
      case 4096:
        break;
      default:
        throw new ValidationException("error.invalid_key_length");
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

  public void addAlternativeName(String alternativeName) {
    List<String> tmp = new ArrayList<>(Arrays.asList(alternativeNames));
    tmp.add(alternativeName);
    alternativeNames = tmp.toArray(new String[tmp.size()]);
  }

  public void addAlternativeNames(String[] alternativeNames) {
    for (String a : alternativeNames) {
      addAlternativeName(a);
    }
  }

  public List<String> getAlternativeNames() {
    return Arrays.asList(alternativeNames);
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }

  public int getKeyLength() {
    return keyLength;
  }
}