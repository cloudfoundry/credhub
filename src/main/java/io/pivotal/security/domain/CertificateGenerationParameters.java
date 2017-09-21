package io.pivotal.security.domain;

import com.google.common.net.InetAddresses;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.request.CertificateGenerationRequestParameters;
import io.pivotal.security.request.GenerationParameters;
import io.pivotal.security.util.CertificateReader;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralNamesBuilder;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.springframework.util.StringUtils;

import static io.pivotal.security.request.CertificateGenerationRequestParameters.*;

public class CertificateGenerationParameters implements GenerationParameters{

  private int keyLength;
  private int duration;
  private boolean selfSigned = false;
  private String caName;
  private boolean isCa = false;

  private X500Name x500Name;
  private GeneralNames alternativeNames;

  private ExtendedKeyUsage extendedKeyUsage;

  private KeyUsage keyUsage;

  public CertificateGenerationParameters(CertificateGenerationRequestParameters generationParameters) {
    this.keyUsage = buildKeyUsage(generationParameters);
    this.x500Name = buildDn(generationParameters);
    this.alternativeNames = buildAlternativeNames(generationParameters);
    this.extendedKeyUsage = buildExtendedKeyUsage(generationParameters);
    this.caName = generationParameters.getCaName();
    this.selfSigned = generationParameters.isSelfSigned();
    this.duration = generationParameters.getDuration();
    this.keyLength = generationParameters.getKeyLength();
    this.isCa = generationParameters.isCa();
  }


  public CertificateGenerationParameters(CertificateReader certificateReader, String caName){
    this.keyUsage = certificateReader.getKeyUsage();
    this.x500Name = certificateReader.getSubjectName();
    this.alternativeNames = certificateReader.getAlternativeNames();
    this.extendedKeyUsage = certificateReader.getExtendedKeyUsage();
    this.caName = caName;
    this.selfSigned = certificateReader.isSelfSigned();
    this.duration = certificateReader.getDurationDays();
    this.keyLength = certificateReader.getKeyLength();
    this.isCa = certificateReader.isCa();
  }

  public int getKeyLength() {
    return keyLength;
  }

  public int getDuration() {
    return duration;
  }

  public String getCaName() {
    return caName;
  }

  public boolean isSelfSigned() {
    return selfSigned;
  }

  public boolean isCa() {
    return isCa;
  }

  public X500Name getX500Name() {
    return x500Name;
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

  private KeyUsage buildKeyUsage(CertificateGenerationRequestParameters keyUsageList) {
    if (keyUsageList.getKeyUsage() == null){
      return null;
    }
    int bitmask = 0;
    for (String keyUsage : keyUsageList.getKeyUsage()) {
      switch (keyUsage) {
        case DIGITAL_SIGNATURE:
          bitmask |= KeyUsage.digitalSignature;
          break;
        case NON_REPUDIATION:
          bitmask |= KeyUsage.nonRepudiation;
          break;
        case KEY_ENCIPHERMENT:
          bitmask |= KeyUsage.keyEncipherment;
          break;
        case DATA_ENCIPHERMENT:
          bitmask |= KeyUsage.dataEncipherment;
          break;
        case KEY_AGREEMENT:
          bitmask |= KeyUsage.keyAgreement;
          break;
        case KEY_CERT_SIGN:
          bitmask |= KeyUsage.keyCertSign;
          break;
        case CRL_SIGN:
          bitmask |= KeyUsage.cRLSign;
          break;
        case ENCIPHER_ONLY:
          bitmask |= KeyUsage.encipherOnly;
          break;
        case DECIPHER_ONLY:
          bitmask |= KeyUsage.decipherOnly;
          break;
        default:
          throw new ParameterizedValidationException("error.invalid_key_usage", keyUsage);
      }
    }
    return new KeyUsage(bitmask);
  }

  private X500Name buildDn(CertificateGenerationRequestParameters params) {
    if (this.x500Name != null) {
      return this.x500Name;
    }

    X500NameBuilder builder = new X500NameBuilder();

    if (!StringUtils.isEmpty(params.getOrganization())) {
      builder.addRDN(BCStyle.O, params.getOrganization());
    }
    if (!StringUtils.isEmpty(params.getState())) {
      builder.addRDN(BCStyle.ST, params.getState());
    }
    if (!StringUtils.isEmpty(params.getCountry())) {
      builder.addRDN(BCStyle.C, params.getCountry());
    }
    if (!StringUtils.isEmpty(params.getCommonName())) {
      builder.addRDN(BCStyle.CN, params.getCommonName());
    }
    if (!StringUtils.isEmpty(params.getOrganizationUnit())) {
      builder.addRDN(BCStyle.OU, params.getOrganizationUnit());
    }
    if (!StringUtils.isEmpty(params.getLocality())) {
      builder.addRDN(BCStyle.L, params.getLocality());
    }

    return builder.build();
  }

  private GeneralNames buildAlternativeNames(CertificateGenerationRequestParameters params) {
    String[] alternativeNamesList = params.getAlternativeNames();
    if (alternativeNamesList == null){
      return null;
    }
    GeneralNamesBuilder builder = new GeneralNamesBuilder();

    for (String name :alternativeNamesList) {
      if (InetAddresses.isInetAddress(name)) {
        builder.addName(new GeneralName(GeneralName.iPAddress, name));
      } else  {
        builder.addName(new GeneralName(GeneralName.dNSName, name));
      }
    }
    return builder.build();
  }

  private ExtendedKeyUsage buildExtendedKeyUsage(CertificateGenerationRequestParameters params) {
    String[] extendedKeyUsageList = params.getExtendedKeyUsage();
    if (extendedKeyUsageList == null){
      return null;
    }
    KeyPurposeId[] keyPurposeIds = new KeyPurposeId[extendedKeyUsageList.length];
    for (int i = 0; i < extendedKeyUsageList.length; i++) {
      switch (extendedKeyUsageList[i]) {
        case SERVER_AUTH:
          keyPurposeIds[i] = KeyPurposeId.id_kp_serverAuth;
          break;
        case CLIENT_AUTH:
          keyPurposeIds[i] = KeyPurposeId.id_kp_clientAuth;
          break;
        case CODE_SIGNING:
          keyPurposeIds[i] = KeyPurposeId.id_kp_codeSigning;
          break;
        case EMAIL_PROTECTION:
          keyPurposeIds[i] = KeyPurposeId.id_kp_emailProtection;
          break;
        case TIMESTAMPING:
          keyPurposeIds[i] = KeyPurposeId.id_kp_timeStamping;
          break;
        default:
          throw new ParameterizedValidationException("error.invalid_extended_key_usage", extendedKeyUsageList[i]);
      }
    }
    return new ExtendedKeyUsage(keyPurposeIds);
  }

}
