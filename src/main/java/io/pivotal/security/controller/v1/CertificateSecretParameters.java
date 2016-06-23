package io.pivotal.security.controller.v1;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.util.StringUtils;

import javax.validation.ValidationException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CertificateSecretParameters {
  // Required Certificate Parameters
  private String organization;
  private String state;
  private String country;

  // Optional Certificate Parameters
  private String commonName;
  private String organizationUnit;
  private String locality;
  private String[] alternativeNames = new String[0];
  private int keyLength = 2048;
  private int durationDays = 365;

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

    if (durationDays < 1 || durationDays > 3650) {
      throw new ValidationException("error.invalid_duration");
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

  public void setDurationDays(int durationDays) {
    this.durationDays = durationDays;
  }

  public int getDurationDays() {
    return durationDays;
  }
}