package org.cloudfoundry.credhub.request;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT;
import static org.apache.commons.lang3.StringUtils.isEmpty;

@SuppressWarnings("PMD.TooManyFields")
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
  private static final Pattern DNS_WILDCARD_PATTERN = Pattern
    .compile("^\\*?(?>(?:\\.[a-zA-Z0-9\\-]+))*$");
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
  private boolean selfSigned;
  private String caName;
  private boolean isCa;
  private String[] alternativeNames;
  private String[] extendedKeyUsage;
  private String[] keyUsage;
  private final List<Integer> validKeyLengths = Arrays.asList(2048, 3072, 4096);
  private final List<String> validExtendedKeyUsages = Arrays
    .asList(SERVER_AUTH, CLIENT_AUTH, CODE_SIGNING, EMAIL_PROTECTION, TIMESTAMPING);

  private final List<String> validKeyUsages = Arrays
    .asList(DIGITAL_SIGNATURE, NON_REPUDIATION, KEY_ENCIPHERMENT, DATA_ENCIPHERMENT,
      KEY_AGREEMENT, KEY_CERT_SIGN, CRL_SIGN, ENCIPHER_ONLY, DECIPHER_ONLY);

  private static final int TEN_YEARS = 3650;
  private static final int ONE_DAY = 1;

  private static void validateParameterLength(final String[] parameterArray, final String parameterName, final int parameterLength) {
    if (parameterArray != null) {
      for (final String parameter : parameterArray) {
        validateParameterLength(parameter, parameterName, parameterLength);
      }
    }
  }

  private static void validateParameterLength(final String parameter, final String parameterName, final int parameterLength) {
    if (!isEmpty(parameter) && parameter.length() > parameterLength) {
      throw new ParameterizedValidationException("error.credential.invalid_certificate_parameter", new Object[]{parameterName, parameterLength});
    }
  }

  public int getKeyLength() {
    return keyLength;
  }

  public void setKeyLength(final int keyLength) {
    this.keyLength = keyLength;
  }

  public int getDuration() {
    return duration;
  }

  public void setDuration(final int duration) {
    this.duration = duration;
  }

  public String getCaName() {
    return caName;
  }

  @JsonProperty("ca")
  public void setCaName(final String caName) {
    this.caName = caName;
  }

  public boolean isSelfSigned() {
    if (isCa() && isEmpty(caName)) {
      selfSigned = true;
    }

    return selfSigned;
  }

  @JsonProperty("self_sign")
  public void setSelfSigned(final boolean selfSigned) {
    this.selfSigned = selfSigned;
  }

  public boolean isCa() {
    return isCa;
  }

  public void setIsCa(final boolean isCa) {
    this.isCa = isCa;
  }

  public String[] getAlternativeNames() {
    return alternativeNames == null ? null : alternativeNames.clone();
  }

  public void setAlternativeNames(final String[] alternativeNames) {
    this.alternativeNames = alternativeNames == null ? null : alternativeNames.clone();
  }

  public String[] getExtendedKeyUsage() {
    return extendedKeyUsage == null ? null : extendedKeyUsage.clone();
  }

  public void setExtendedKeyUsage(final String[] extendedKeyUsage) {
    this.extendedKeyUsage = extendedKeyUsage == null ? null : extendedKeyUsage.clone();
  }

  public String[] getKeyUsage() {
    return keyUsage == null ? null : keyUsage.clone();
  }

  public void setKeyUsage(final String[] keyUsage) {
    this.keyUsage = keyUsage == null ? null : keyUsage.clone();
  }

  public String getOrganization() {
    return organization;
  }

  public void setOrganization(final String organization) {
    this.organization = organization;
  }

  public String getState() {
    return state;
  }

  public void setState(final String state) {
    this.state = state;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(final String country) {
    this.country = country;
  }

  public String getCommonName() {
    return commonName;
  }

  public void setCommonName(final String commonName) {
    this.commonName = commonName;
  }

  public String getOrganizationUnit() {
    return organizationUnit;
  }

  public void setOrganizationUnit(final String organizationUnit) {
    this.organizationUnit = organizationUnit;
  }

  public String getLocality() {
    return locality;
  }

  public void setLocality(final String locality) {
    this.locality = locality;
  }

  @SuppressWarnings("PMD.NPathComplexity")
  public void validate() {
    if (isEmpty(organization)
      && isEmpty(state)
      && isEmpty(locality)
      && isEmpty(organizationUnit)
      && isEmpty(commonName)
      && isEmpty(country)
    ) {
      throw new ParameterizedValidationException("error.missing_certificate_parameters");
    } else if (isEmpty(caName) && !selfSigned && !isCa) {
      throw new ParameterizedValidationException("error.missing_signing_ca");
    } else if (!isEmpty(caName) && selfSigned) {
      throw new ParameterizedValidationException("error.ca_and_self_sign");
    }

    if (!validKeyLengths.contains(keyLength)) {
      throw new ParameterizedValidationException("error.invalid_key_length");
    }

    if (alternativeNames != null) {
      for (final String name : alternativeNames) {
        if (
          !InetAddresses.isInetAddress(name)
            && !(
              InternetDomainName.isValid(name)
              || DNS_WILDCARD_PATTERN.matcher(name).matches()
            )
        ) {
          throw new ParameterizedValidationException("error.invalid_alternate_name");
        }
      }
    }

    if (extendedKeyUsage != null) {
      for (final String extendedKey : extendedKeyUsage) {
        if (!validExtendedKeyUsages.contains(extendedKey)) {
          throw new ParameterizedValidationException("error.invalid_extended_key_usage",
            extendedKey);
        }
      }
    }

    if (keyUsage != null) {
      for (final String keyUse : keyUsage) {
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
    validateParameterLength(alternativeNames, "alternative name", 253);
  }
}
