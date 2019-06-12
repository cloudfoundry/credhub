package org.cloudfoundry.credhub.generators;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cloudfoundry.credhub.domain.CertificateGenerationParameters;
import org.cloudfoundry.credhub.util.CurrentTimeProvider;

import static org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue;

@Component
public class SignedCertificateGenerator {

  private final CurrentTimeProvider timeProvider;
  private final RandomSerialNumberGenerator serialNumberGenerator;
  private final JcaX509ExtensionUtils jcaX509ExtensionUtils;
  private final JcaContentSignerBuilder jcaContentSignerBuilder;
  private final JcaX509CertificateConverter jcaX509CertificateConverter;

  @Autowired
  SignedCertificateGenerator(
    final CurrentTimeProvider timeProvider,
    final RandomSerialNumberGenerator serialNumberGenerator,
    final JcaContentSignerBuilder jcaContentSignerBuilder,
    final JcaX509CertificateConverter jcaX509CertificateConverter
  ) throws Exception {
    super();
    this.timeProvider = timeProvider;
    this.serialNumberGenerator = serialNumberGenerator;
    this.jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
    this.jcaContentSignerBuilder = jcaContentSignerBuilder;
    this.jcaX509CertificateConverter = jcaX509CertificateConverter;
  }

  public X509Certificate getSelfSigned(final KeyPair keyPair, final CertificateGenerationParameters params) throws Exception {
    final SubjectKeyIdentifier keyIdentifier = getSubjectKeyIdentifierFromKeyInfo(keyPair.getPublic());

    return getSignedByIssuer(
      null,
      keyPair.getPrivate(),
      params.getX500Principal(),
      keyIdentifier,
      keyPair,
      params
    );
  }

  public X509Certificate getSignedByIssuer(
    final KeyPair keyPair,
    final CertificateGenerationParameters params,
    final X509Certificate caCertificate,
    final PrivateKey caPrivateKey) throws Exception {
    return getSignedByIssuer(
      caCertificate,
      caPrivateKey,
      getSubjectNameFrom(caCertificate),
      getSubjectKeyIdentifierFrom(caCertificate), keyPair,
      params
    );
  }

  private X509Certificate getSignedByIssuer(
    final X509Certificate issuerCertificate,
    final PrivateKey issuerKey,
    final X500Principal issuerDn,
    final SubjectKeyIdentifier caSubjectKeyIdentifier,
    final KeyPair keyPair,
    final   CertificateGenerationParameters params) throws Exception {
    final Instant now = Instant.from(timeProvider.getInstant());

    final BigInteger certificateSerialNumber = serialNumberGenerator.generate();

    final JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
      issuerDn,
      certificateSerialNumber,
      Date.from(now),
      Date.from(now.plus(Duration.ofDays(params.getDuration()))),
      params.getX500Principal(),
      keyPair.getPublic()
    );

    certificateBuilder.addExtension(
      Extension.subjectKeyIdentifier,
      false,
      getSubjectKeyIdentifierFromKeyInfo(keyPair.getPublic()));
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
      final PublicKey issuerPublicKey = issuerCertificate != null ? issuerCertificate.getPublicKey() : keyPair.getPublic();
      final AuthorityKeyIdentifier authorityKeyIdentifier = jcaX509ExtensionUtils
        .createAuthorityKeyIdentifier(issuerPublicKey);

      certificateBuilder
        .addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
    }

    certificateBuilder
      .addExtension(Extension.basicConstraints, true, new BasicConstraints(params.isCa()));

    final ContentSigner contentSigner = jcaContentSignerBuilder.build(issuerKey);

    final X509CertificateHolder holder = certificateBuilder.build(contentSigner);

    return jcaX509CertificateConverter.getCertificate(holder);
  }

  private SubjectKeyIdentifier getSubjectKeyIdentifierFromKeyInfo(final PublicKey publicKey) {
    return jcaX509ExtensionUtils.createSubjectKeyIdentifier(publicKey);
  }

  private X500Principal getSubjectNameFrom(final X509Certificate certificate) throws IOException, CertificateException {
    return new X500Principal(certificate.getSubjectX500Principal().getEncoded());
  }

  private SubjectKeyIdentifier getSubjectKeyIdentifierFrom(final X509Certificate certificate) throws Exception {
    final byte[] extensionValue = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    return extensionValue == null ?
      new SubjectKeyIdentifier(null) :
      SubjectKeyIdentifier.getInstance(parseExtensionValue(extensionValue));
  }
}
