package io.pivotal.security.controller.v1;

import io.pivotal.security.entity.NamedCertificateSecret;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.regex.Pattern;

import static java.lang.Math.toIntExact;
import static java.time.temporal.ChronoUnit.DAYS;

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
  private boolean selfSign = false;
  private String caName = "default";
  private boolean isCA = false;

  // Used for regen; contains RDN (NOT key length, duration days, or alternative names)
  private X500Name x500Name;
  private GeneralNames alternativeNames;

  private ExtendedKeyUsage extendedKeyUsage;
  private KeyUsage keyUsage;

  public CertificateSecretParameters() {
  }

  public CertificateSecretParameters(String certificate, String caName) {
    try {
      X509Certificate x509Cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
          .generateCertificate(new ByteArrayInputStream(certificate.getBytes()));

      X509CertificateHolder x509CertHolder = (X509CertificateHolder) (new PEMParser((new StringReader(certificate))).readObject());

      this.x500Name = extractX500Name(x509Cert);
      this.keyLength = extractKeyLength(x509Cert);
      this.selfSign = extractIsSelfSigned(x509Cert);
      this.durationDays = extractDurationDays(x509Cert);

      this.extendedKeyUsage = extractExtendedKeyUsage(x509CertHolder);
      this.alternativeNames = extractAlternativeNames(x509CertHolder);
      this.keyUsage = extractKeyUsage(x509CertHolder);

      this.caName = caName;

      this.type = NamedCertificateSecret.SECRET_TYPE; // Delete when Certificate Authorities are removed.
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
          throw new ParameterizedValidationException("error.invalid_extended_key_usage", Arrays.asList(extendedKeyUsageList[i]));
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
          throw new ParameterizedValidationException("error.invalid_key_usage", Arrays.asList(keyUsage));
      }
    }
    this.keyUsage = new KeyUsage(bitmask);
    return this;
  }

  public ASN1Object extractAlternativeNames() {
    return alternativeNames;
  }

  public ExtendedKeyUsage getExtendedKeyUsage() {
    return extendedKeyUsage;
  }

  public KeyUsage getKeyUsage() {
    return keyUsage;
  }

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

  public boolean getSelfSign() {
    return selfSign;
  }

  public CertificateSecretParameters setSelfSign(boolean selfSign) {
    this.selfSign = selfSign;
    return this;
  }

  public boolean getIsCA() {
    return isCA;
  }

  public CertificateSecretParameters setIsCa(boolean isCA) {
    this.isCA = isCA;
    return this;
  }

  public String getType() {
    return type;
  }

  public CertificateSecretParameters setType(String type) {
    this.type = type;
    return this;
  }

  private static boolean extractIsSelfSigned(X509Certificate cert) {
    final String issuerName = cert.getIssuerDN().getName();
    final String subjectName = cert.getSubjectDN().getName();

    if (!issuerName.equals(subjectName)) {
      return false;
    } else {
      try {
        cert.verify(cert.getPublicKey());
        return true;
      } catch(SignatureException | InvalidKeyException e) {
        return false;
      } catch(Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  private static X500Name extractX500Name(X509Certificate cert) {
    return new X500Name(cert.getSubjectDN().getName());
  }

  private static int extractKeyLength(X509Certificate cert) {
    return ((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength();
  }

  private int extractDurationDays(X509Certificate cert) {
    return toIntExact(DAYS.between(
        cert.getNotBefore().toInstant(),
        cert.getNotAfter().toInstant()
    ));
  }

  private static GeneralNames extractAlternativeNames(X509CertificateHolder certificateHolder) throws CertificateParsingException {
    Extension encodedAlternativeNames = certificateHolder.getExtension(Extension.subjectAlternativeName);
    return encodedAlternativeNames != null ? GeneralNames.getInstance(encodedAlternativeNames.getParsedValue()) : null;
  }

  private static ExtendedKeyUsage extractExtendedKeyUsage(X509CertificateHolder certificateHolder) throws CertificateParsingException {
    return ExtendedKeyUsage.fromExtensions(certificateHolder.getExtensions());
  }

  private static KeyUsage extractKeyUsage(X509CertificateHolder certificateHolder) {
    return KeyUsage.fromExtensions(certificateHolder.getExtensions());
  }
}
