package io.pivotal.security.controller.v1;

import io.pivotal.security.constants.KeyUsageExtensions;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static com.google.common.collect.Lists.newArrayList;

public class CertificateSecretParameters implements RequestParameters {
  private static final Pattern IP_ADDRESS_PATTERN = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/\\d+)?$");
  private static final Pattern BAD_IP_ADDRESS_PATTERN = Pattern.compile("^(\\d+\\.){3}\\d+$");
  private static final Pattern DNS_PATTERN_INCLUDING_LEADING_WILDCARD = Pattern.compile("^(\\*\\.)?(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$");

  private String type;

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
  private String caName = "default";

  // Used for regen; contains RDN (NOT key length, duration days, or alternative names)
  private X500Name x500Name;
  private GeneralNames alternativeNames;

  private ExtendedKeyUsage extendedKeyUsages;

  public CertificateSecretParameters() {
  }

  public CertificateSecretParameters(String certificate) {
    try {
      this.x500Name = getSubjectX500Name(certificate);
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

  public X500Name getDN() {
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

  public CertificateSecretParameters addAlternativeNames(Extension encodedAlternativeNames) {
    if (encodedAlternativeNames != null) {
      this.alternativeNames = GeneralNames.getInstance(ASN1Sequence.getInstance(encodedAlternativeNames.getParsedValue()));
    }

    return this;
  }

  public CertificateSecretParameters addAlternativeNames(String... alternativeNames) {
    GeneralName[] genNames = new GeneralName[alternativeNames.length];
    for (int i = 0; i < alternativeNames.length; i++) {
      String name = alternativeNames[i];
      if (IP_ADDRESS_PATTERN.matcher(name).matches()) {
        genNames[i] = new GeneralName(GeneralName.iPAddress, name);
      } else if (BAD_IP_ADDRESS_PATTERN.matcher(name).matches()) {
        throw new ParameterizedValidationException("error.invalid_alternate_name");
      } else if (DNS_PATTERN_INCLUDING_LEADING_WILDCARD.matcher(name).matches()) {
        genNames[i] = new GeneralName(GeneralName.dNSName, name);
      } else {
        throw new ParameterizedValidationException("error.invalid_alternate_name");
      }
    }

    this.alternativeNames = new GeneralNames(genNames);

    return this;
  }

  public CertificateSecretParameters addExtendedKeyUsages(Extension encodedExtendedKeyUsages) {
    if (encodedExtendedKeyUsages != null) {
      DLSequence parsedValue = (DLSequence) encodedExtendedKeyUsages.getParsedValue();
      final ArrayList<ASN1ObjectIdentifier> objectIdentifiers = Collections.list(parsedValue.getObjects());
      List<KeyPurposeId> keyList = newArrayList();
      for (ASN1ObjectIdentifier oid: objectIdentifiers) {
        final KeyUsageExtensions extension = KeyUsageExtensions.getExtension(oid.getId());
        switch(extension.name().toLowerCase()) {
          case "server_auth":
            keyList.add(KeyPurposeId.id_kp_serverAuth);
            break;
          case "client_auth":
            keyList.add(KeyPurposeId.id_kp_clientAuth);
            break;
          case "code_signing":
            keyList.add(KeyPurposeId.id_kp_codeSigning);
            break;
          case "email_protection":
            keyList.add(KeyPurposeId.id_kp_emailProtection);
            break;
          case "time_stamping":
            keyList.add(KeyPurposeId.id_kp_timeStamping);
            break;
          default:
            throw new ParameterizedValidationException("error.invalid_extended_key_usage", Arrays.asList(extension.toString()));
        }
      }
      this.extendedKeyUsages = new ExtendedKeyUsage(keyList.toArray(new KeyPurposeId[0]));
    }
    return this;
  }

  public CertificateSecretParameters addExtendedKeyUsages(String... extendedKeyUsages) {
    KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsages.length];
    for (int i = 0; i < extendedKeyUsages.length; i++) {
      switch(extendedKeyUsages[i]) {
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
          throw new ParameterizedValidationException("error.invalid_extended_key_usage", Arrays.asList(extendedKeyUsages[i]));
      }
    }
    this.extendedKeyUsages = new ExtendedKeyUsage(keyPurposeIds);
    return this;
  }

  public ASN1Object getAlternativeNames() {
    return alternativeNames;
  }

  public ASN1Object getExtendedKeyUsages() { return extendedKeyUsages; }

  public CertificateSecretParameters setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    return this;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public CertificateSecretParameters setDurationDays(int durationDays) {
    this.durationDays = durationDays;
    return this;
  }

  public int getDurationDays() {
    return durationDays;
  }

  public String getCaName() {
    return caName;
  }

  public CertificateSecretParameters setCaName(String caName) {
    this.caName = caName;
    return this;
  }

  public String getType() {
    return type;
  }

  public CertificateSecretParameters setType(String type) {
    this.type = type;
    return this;
  }

  private static X500Name getSubjectX500Name(String cert) throws IOException, CertificateException, NoSuchProviderException {
    X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
        .generateCertificate(new ByteArrayInputStream(cert.getBytes()));
    return new X500Name(certificate.getSubjectDN().getName());
  }
}
