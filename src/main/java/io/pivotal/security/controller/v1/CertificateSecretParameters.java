package io.pivotal.security.controller.v1;

import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.util.CertificateReader;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.util.StringUtils;

public class CertificateSecretParameters implements RequestParameters {

  private static final Pattern DNS_WILDCARD_PATTERN = Pattern
      .compile("^\\*?(?:\\.[a-zA-Z0-9\\-]+)*$");

  // Parameters used in RDN; at least one must be set
  private String organization;
  private String state;
  private String country;
  private String commonName;
  private String organizationUnit;
  private String locality;

  // Optional Certificate Parameters (not used in RDN)
  private int keyLength = 2048;
  private int durationDays = 365;
  private boolean selfSigned = false;
  private String caName;
  private boolean isCa = false;

  // Used for regen; contains RDN (NOT key length, duration days, or alternative names)
  private X500Name x500Name;
  private GeneralNames alternativeNames;

  private ExtendedKeyUsage extendedKeyUsage;
  private KeyUsage keyUsage;

  public CertificateSecretParameters() {
  }

  public CertificateSecretParameters(CertificateReader certificateReader, String caName) {
    try {
      this.x500Name = certificateReader.getSubjectName();
      this.keyLength = certificateReader.getKeyLength();
      this.selfSigned = certificateReader.isSelfSigned();
      this.durationDays = certificateReader.getDurationDays();

      this.extendedKeyUsage = certificateReader.getExtendedKeyUsage();
      this.alternativeNames = certificateReader.getAlternativeNames();
      this.keyUsage = certificateReader.getKeyUsage();
      this.isCa = certificateReader.isCa();

      this.caName = caName;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

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

    switch (keyLength) {
      case 2048:
      case 3072:
      case 4096:
        break;
      default:
        throw new ParameterizedValidationException("error.invalid_key_length");
    }

    if (durationDays < 1 || durationDays > 3650) {
      throw new ParameterizedValidationException("error.invalid_duration");
    }
  }

  public X500Name getDn() {
    if (this.x500Name != null) {
      return this.x500Name;
    }

    X500NameBuilder builder = new X500NameBuilder();

    if (!StringUtils.isEmpty(organization)) {
      builder.addRDN(BCStyle.O, organization);
    }
    if (!StringUtils.isEmpty(state)) {
      builder.addRDN(BCStyle.ST, state);
    }
    if (!StringUtils.isEmpty(country)) {
      builder.addRDN(BCStyle.C, country);
    }
    if (!StringUtils.isEmpty(commonName)) {
      builder.addRDN(BCStyle.CN, commonName);
    }
    if (!StringUtils.isEmpty(organizationUnit)) {
      builder.addRDN(BCStyle.OU, organizationUnit);
    }
    if (!StringUtils.isEmpty(locality)) {
      builder.addRDN(BCStyle.L, locality);
    }

    return builder.build();
  }

  public CertificateSecretParameters addAlternativeNames(String... alternativeNames) {
    GeneralName[] genNames = new GeneralName[alternativeNames.length];

    for (int i = 0; i < alternativeNames.length; i++) {
      String name = alternativeNames[i];

      if (InetAddresses.isInetAddress(name)) {
        genNames[i] = new GeneralName(GeneralName.iPAddress, name);
      } else if (InternetDomainName.isValid(name) || DNS_WILDCARD_PATTERN.matcher(name).matches()) {
        // Check for wildcard case, as InternetDomainName doesn't cover that.
        genNames[i] = new GeneralName(GeneralName.dNSName, name);
      } else {
        throw new ParameterizedValidationException("error.invalid_alternate_name");
      }
    }

    this.alternativeNames = new GeneralNames(genNames);

    return this;
  }

  public CertificateSecretParameters addExtendedKeyUsage(String... extendedKeyUsageList) {
    KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsageList.length];
    for (int i = 0; i < extendedKeyUsageList.length; i++) {
      switch (extendedKeyUsageList[i]) {
        case "server_auth":
          keyPurposeIds[i] = KeyPurposeId.id_kp_serverAuth;
          break;
        case "client_auth":
          keyPurposeIds[i] = KeyPurposeId.id_kp_clientAuth;
          break;
        case "code_signing":
          keyPurposeIds[i] = KeyPurposeId.id_kp_codeSigning;
          break;
        case "email_protection":
          keyPurposeIds[i] = KeyPurposeId.id_kp_emailProtection;
          break;
        case "time_stamping":
          keyPurposeIds[i] = KeyPurposeId.id_kp_timeStamping;
          break;
        default:
          throw new ParameterizedValidationException("error.invalid_extended_key_usage",
              extendedKeyUsageList[i]);
      }
    }
    this.extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds);
    return this;
  }

  public CertificateSecretParameters addKeyUsage(String... keyUsageList) {
    int bitmask = 0;
    for (String keyUsage : keyUsageList) {
      switch (keyUsage) {
        case "digital_signature":
          bitmask |= KeyUsage.digitalSignature;
          break;
        case "non_repudiation":
          bitmask |= KeyUsage.nonRepudiation;
          break;
        case "key_encipherment":
          bitmask |= KeyUsage.keyEncipherment;
          break;
        case "data_encipherment":
          bitmask |= KeyUsage.dataEncipherment;
          break;
        case "key_agreement":
          bitmask |= KeyUsage.keyAgreement;
          break;
        case "key_cert_sign":
          bitmask |= KeyUsage.keyCertSign;
          break;
        case "crl_sign":
          bitmask |= KeyUsage.cRLSign;
          break;
        case "encipher_only":
          bitmask |= KeyUsage.encipherOnly;
          break;
        case "decipher_only":
          bitmask |= KeyUsage.decipherOnly;
          break;
        default:
          throw new ParameterizedValidationException("error.invalid_key_usage", keyUsage);
      }
    }
    this.keyUsage = new KeyUsage(bitmask);
    return this;
  }

  public GeneralNames getAlternativeNames() {
    return alternativeNames;
  }

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public KeyUsage getKeyUsage() {
    return keyUsage;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public CertificateSecretParameters setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    return this;
  }

  public int getDurationDays() {
    return durationDays;
  }

  public CertificateSecretParameters setDurationDays(int durationDays) {
    this.durationDays = durationDays;
    return this;
  }

  public String getCaName() {
    return caName;
  }

  public CertificateSecretParameters setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public CertificateSecretParameters setSelfSigned(boolean selfSigned) {
    this.selfSigned = selfSigned;
    return this;
  }

  public boolean isCa() {
    return isCa;
  }

  public CertificateSecretParameters setIsCa(boolean isCa) {
    this.isCa = isCa;
    return this;
  }
}
