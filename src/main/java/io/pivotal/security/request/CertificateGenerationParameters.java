package io.pivotal.security.request;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;
import static org.apache.commons.lang3.StringUtils.isEmpty;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.util.StringUtils;

@JsonInclude(NON_DEFAULT)
public class CertificateGenerationParameters {

  // Parameters used in RDN; at least one must be set
  private String organization;

  private String state;

  private String country;
  private String commonName;
  private String organizationUnit;
  private String locality;
  // Optional Certificate Parameters (not used in RDN)
  private int keyLength = 2048;

  private int duration = 365;
  private boolean selfSigned = false;
  private String caName;
  private boolean isCa = false;
  private String[] alternativeNames;

  private String[] extendedKeyUsage;
  private String[] keyUsage;
  private List<Integer> validKeyLengths = Arrays.asList(2048, 3072, 4096);
  private static final Pattern DNS_WILDCARD_PATTERN = Pattern
      .compile("^\\*?(?:\\.[a-zA-Z0-9\\-]+)*$");

  private List<String> validExtendedKeyUsages = Arrays
      .asList("server_auth", "client_auth", "code_signing", "email_protection", "time_stamping");

  private List<String> validKeyUsages = Arrays
      .asList("digital_signature", "non_repudiation", "key_encipherment", "data_enchipherment",
          "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only");

  private int TEN_YEARS = 3650;
  private int ONE_DAY = 1;

  public CertificateGenerationParameters() {
  }

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

  public int getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
  }

  public int getDuration() {
    return duration;
  }

  public void setDuration(int duration) {
    this.duration = duration;
  }


  public String getCaName() {
    return caName;
  }

  @JsonProperty("ca")
  public void setCaName(String caName) {
    this.caName = caName;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  @JsonProperty("self_sign")
  public void setSelfSigned(boolean selfSigned) {
    this.selfSigned = selfSigned;
  }

  public boolean isCa() {
    return isCa;
  }

  public void setIsCa(boolean isCa) {
    this.isCa = isCa;
  }

  public String[] getAlternativeNames() {
    return alternativeNames;
  }

  public void setAlternativeNames(String[] alternativeNames) {
    this.alternativeNames = alternativeNames;
  }

  public String[] getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public void setExtendedKeyUsage(String[] extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage;
  }

  public String[] getKeyUsage() {
    return keyUsage;
  }

  public void setKeyUsage(String[] keyUsage) {
    this.keyUsage = keyUsage;
  }

  public String getOrganization() {
    return organization;
  }

  public String getState() {
    return state;
  }

  public String getCountry() {
    return country;
  }

  public String getCommonName() {
    return commonName;
  }

  public String getOrganizationUnit() {
    return organizationUnit;
  }

  public String getLocality() {
    return locality;
  }

  public void validate() {
    if (isCa() && isEmpty(caName)) {
      selfSigned = true;
    }

    if (StringUtils.isEmpty(organization)
        && StringUtils.isEmpty(state)
        && StringUtils.isEmpty(locality)
        && StringUtils.isEmpty(organizationUnit)
        && StringUtils.isEmpty(commonName)
        && StringUtils.isEmpty(country)) {
      throw new ParameterizedValidationException("error.missing_certificate_parameters");
    } else if (StringUtils.isEmpty(caName) && !selfSigned && !isCa) {
      throw new ParameterizedValidationException("error.missing_signing_ca");
    } else if (!StringUtils.isEmpty(caName) && selfSigned) {
      throw new ParameterizedValidationException("error.ca_and_self_sign");
    }

    if (!validKeyLengths.contains(keyLength)) {
      throw new ParameterizedValidationException("error.invalid_key_length");
    }

    if (alternativeNames != null) {
      for (String name : alternativeNames) {
        if (!InetAddresses.isInetAddress(name) && !(InternetDomainName.isValid(name)
            || DNS_WILDCARD_PATTERN.matcher(name).matches())) {
          throw new ParameterizedValidationException("error.invalid_alternate_name");
        }
      }
    }

    if (extendedKeyUsage != null) {
      for (String extendedKey : extendedKeyUsage) {
        if (!validExtendedKeyUsages.contains(extendedKey)) {
          throw new ParameterizedValidationException("error.invalid_extended_key_usage",
              extendedKey);
        }
      }
    }

    if (keyUsage != null) {
      for (String keyUse : keyUsage) {
        if (!validKeyUsages.contains(keyUse)) {
          throw new ParameterizedValidationException("error.invalid_key_usage",
              keyUse);
        }
      }
    }

    if (duration < ONE_DAY || duration > TEN_YEARS) {
      throw new ParameterizedValidationException("error.invalid_duration");
    }
  }
}
