package org.cloudfoundry.credhub.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@JsonInclude(NON_DEFAULT)
public class CertificateGenerationRequestParameters {
  public static final String SERVER_AUTH = "server_auth";
  public static final String CLIENT_AUTH = "client_auth";
  public static final String CODE_SIGNING = "code_signing";
  public static final String EMAIL_PROTECTION = "email_protection";
  public static final String TIMESTAMPING = "timestamping";
  public static final String DIGITAL_SIGNATURE = "digital_signature";
  public static final String NON_REPUDIATION = "non_repudiation";
  public static final String KEY_ENCIPHERMENT = "key_encipherment";
  public static final String DATA_ENCIPHERMENT = "data_encipherment";
  public static final String KEY_AGREEMENT = "key_agreement";
  public static final String KEY_CERT_SIGN = "key_cert_sign";
  public static final String CRL_SIGN = "crl_sign";
  public static final String ENCIPHER_ONLY = "encipher_only";
  public static final String DECIPHER_ONLY = "decipher_only";

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
      .compile("^\\*?(?>(?:\\.[a-zA-Z0-9\\-]+))*$");

  private List<String> validExtendedKeyUsages = Arrays
      .asList(SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIMESTAMPING);

  private List<String> validKeyUsages = Arrays
      .asList(DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT,
          KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY, DECIPHER_ONLY);

  private int TEN_YEARS = 3650;
  private int ONE_DAY = 1;

  public CertificateGenerationRequestParameters() {
  }

  public CertificateGenerationRequestParameters setCommonName(String commonName) {
    this.commonName = commonName;
    return this;
  }

  public CertificateGenerationRequestParameters setOrganization(String organization) {
    this.organization = organization;
    return this;
  }

  public CertificateGenerationRequestParameters setOrganizationUnit(String organizationUnit) {
    this.organizationUnit = organizationUnit;
    return this;
  }

  public CertificateGenerationRequestParameters setLocality(String locality) {
    this.locality = locality;
    return this;
  }

  public CertificateGenerationRequestParameters setState(String state) {
    this.state = state;
    return this;
  }

  public CertificateGenerationRequestParameters setCountry(String country) {
    this.country = country;
    return this;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public CertificateGenerationRequestParameters setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    return this;
  }

  public int getDuration() {
    return duration;
  }

  public CertificateGenerationRequestParameters setDuration(int duration) {
    this.duration = duration;
    return this;
  }


  public String getCaName() {
    return caName;
  }

  @JsonProperty("ca")
  public CertificateGenerationRequestParameters setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public boolean isSelfSigned() {
    if (isCa() && isEmpty(caName)) {
      selfSigned = true;
    }

    return selfSigned;
  }

  @JsonProperty("self_sign")
  public CertificateGenerationRequestParameters setSelfSigned(boolean selfSigned) {
    this.selfSigned = selfSigned;
    return this;
  }

  public boolean isCa() {
    return isCa;
  }

  public CertificateGenerationRequestParameters setIsCa(boolean isCa) {
    this.isCa = isCa;
    return this;
  }

  public String[] getAlternativeNames() {
    return alternativeNames == null ? null : alternativeNames.clone();
  }

  public CertificateGenerationRequestParameters setAlternativeNames(String[] alternativeNames) {
    this.alternativeNames = alternativeNames == null ? null : alternativeNames.clone();
    return this;
  }

  public String[] getExtendedKeyUsage() {
    return extendedKeyUsage == null ? null: extendedKeyUsage.clone();
  }

  public CertificateGenerationRequestParameters setExtendedKeyUsage(String[] extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage == null ? null: extendedKeyUsage.clone();
    return this;
  }

  public String[] getKeyUsage() {
    return keyUsage == null ? null : keyUsage.clone();
  }

  public CertificateGenerationRequestParameters setKeyUsage(String[] keyUsage) {
    this.keyUsage = keyUsage == null ? null : keyUsage.clone();
    return this;
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

    validateParameterLength(commonName, "common name", 64);
    validateParameterLength(organization, "organization", 64);
    validateParameterLength(organizationUnit, "organization unit", 64);
    validateParameterLength(locality, "locality", 128);
    validateParameterLength(state, "state", 128);
    validateParameterLength(country, "country", 2);
    validateParameterLength(alternativeNames, "alternative name", 64);
  }

  private static void validateParameterLength(String[] parameterArray, String parameterName, int parameterLength) {
    if (parameterArray != null) {
      for (String parameter : parameterArray) {
        validateParameterLength(parameter, parameterName, parameterLength);
      }
    }
  }

  private static void validateParameterLength(String parameter, String parameterName, int parameterLength) {
    if (!isEmpty(parameter) && parameter.length() > parameterLength) {
      throw new ParameterizedValidationException("error.credential.invalid_certificate_parameter", new Object[]{parameterName, parameterLength});
    }
  }
}
