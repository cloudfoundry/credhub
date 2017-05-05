package io.pivotal.security.generator;

import static org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue;

import io.pivotal.security.credential.CertificateCredentialValue;
import io.pivotal.security.domain.CertificateParameters;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.stereotype.Component;

@Component
public class SignedCertificateGenerator {

  private final DateTimeProvider timeProvider;
  private final RandomSerialNumberGenerator serialNumberGenerator;
  private final X509ExtensionUtils x509ExtensionUtils;
  private JcaContentSignerBuilder jcaContentSignerBuilder;
  private JcaX509CertificateConverter jcaX509CertificateConverter;
  private final BouncyCastleProvider jceProvider;

  @Autowired
  SignedCertificateGenerator(
      DateTimeProvider timeProvider,
      RandomSerialNumberGenerator serialNumberGenerator,
      X509ExtensionUtils x509ExtensionUtils,
      JcaContentSignerBuilder jcaContentSignerBuilder,
      JcaX509CertificateConverter jcaX509CertificateConverter,
      BouncyCastleProvider jceProvider
  ) throws Exception {
    this.timeProvider = timeProvider;
    this.serialNumberGenerator = serialNumberGenerator;
    this.x509ExtensionUtils = x509ExtensionUtils;
    this.jcaContentSignerBuilder = jcaContentSignerBuilder;
    this.jcaX509CertificateConverter = jcaX509CertificateConverter;
    this.jceProvider = jceProvider;
  }

  X509Certificate getSelfSigned(KeyPair keyPair, CertificateParameters params) throws Exception {
    SubjectKeyIdentifier keyIdentifier = getSubjectKeyIdentifierFromKeyInfo(getKeyInfoFromKeyPair(keyPair));

    return getSignedByIssuer(params.getX500Name(), keyPair.getPrivate(), keyPair, params, keyIdentifier, null);
  }

  X509Certificate getSignedByIssuer(
      KeyPair keyPair,
      CertificateParameters params,
      CertificateCredentialValue ca
  ) throws Exception {

    return getSignedByIssuer(
        getSubjectNameFrom(ca),
        getPrivateKeyFrom(ca),
        keyPair,
        params,
        getSubjectKeyIdentifierFrom(ca),
        getSerialNumberFrom(ca)
    );
  }

  private X509Certificate getSignedByIssuer(
      X500Name issuerDn,
      PrivateKey issuerKey,
      KeyPair keyPair,
      CertificateParameters params,
      SubjectKeyIdentifier caSubjectKeyIdentifier,
      BigInteger caSerialNumber) throws Exception {
    Instant now = timeProvider.getNow().toInstant();
    SubjectPublicKeyInfo publicKeyInfo = getKeyInfoFromKeyPair(keyPair);

    BigInteger certificateSerialNumber = serialNumberGenerator.generate();
    caSerialNumber = caSerialNumber != null ? caSerialNumber : certificateSerialNumber;

    final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
        issuerDn,
        certificateSerialNumber,
        Date.from(now),
        Date.from(now.plus(Duration.ofDays(params.getDuration()))),
        params.getX500Name(),
        publicKeyInfo
    );

    certificateBuilder.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        getSubjectKeyIdentifierFromKeyInfo(publicKeyInfo));
    if (params.getAlternativeNames() != null) {
      certificateBuilder
          .addExtension(Extension.subjectAlternativeName, false, params.getAlternativeNames());
    }

    if (params.getKeyUsage() != null) {
      certificateBuilder.addExtension(Extension.keyUsage, true, params.getKeyUsage());
    }

    if (params.getExtendedKeyUsage() != null) {
      certificateBuilder
          .addExtension(Extension.extendedKeyUsage, false, params.getExtendedKeyUsage());
    }

    if (caSubjectKeyIdentifier.getKeyIdentifier() != null) {
      AuthorityKeyIdentifier authorityKeyIdentifier =
          new AuthorityKeyIdentifier(
              caSubjectKeyIdentifier.getKeyIdentifier(),
              new GeneralNames(new GeneralName(issuerDn)),
              caSerialNumber);

      certificateBuilder
          .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
    }

    certificateBuilder
        .addExtension(Extension.basicConstraints, true, new BasicConstraints(params.isCa()));

    ContentSigner contentSigner = jcaContentSignerBuilder.build(issuerKey);

    X509CertificateHolder holder = certificateBuilder.build(contentSigner);

    return jcaX509CertificateConverter.getCertificate(holder);
  }

  private SubjectKeyIdentifier getSubjectKeyIdentifierFromKeyInfo(SubjectPublicKeyInfo publicKeyInfo) {
    return x509ExtensionUtils.createSubjectKeyIdentifier(publicKeyInfo);
  }

  private SubjectPublicKeyInfo getKeyInfoFromKeyPair(KeyPair keyPair) {
    return SubjectPublicKeyInfo
        .getInstance(keyPair.getPublic().getEncoded());
  }

  private X500Name getSubjectNameFrom(CertificateCredentialValue ca) throws IOException, CertificateException {
    X509Certificate certificate = getX509Certificate(ca);
    return new X500Name(certificate.getSubjectDN().getName());
  }

  private PrivateKey getPrivateKeyFrom(CertificateCredentialValue ca)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    PEMParser pemParser = new PEMParser(new StringReader(ca.getPrivateKey()));
    PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  private SubjectKeyIdentifier getSubjectKeyIdentifierFrom(CertificateCredentialValue ca) throws Exception {
    X509Certificate certificate = getX509Certificate(ca);

    byte[] extensionValue = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    return extensionValue == null ?
        new SubjectKeyIdentifier(null) :
        SubjectKeyIdentifier.getInstance(parseExtensionValue(extensionValue));
  }

  private BigInteger getSerialNumberFrom(CertificateCredentialValue ca) throws Exception {
    X509Certificate certificate = getX509Certificate(ca);

    return certificate.getSerialNumber();
  }

  private X509Certificate getX509Certificate(CertificateCredentialValue ca) throws CertificateException {
    return (X509Certificate) CertificateFactory
        .getInstance("X.509", jceProvider)
        .generateCertificate(new ByteArrayInputStream(ca.getCertificate().getBytes()));
  }
}
