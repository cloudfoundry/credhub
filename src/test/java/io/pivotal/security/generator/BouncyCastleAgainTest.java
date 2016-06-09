package io.pivotal.security.generator;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.junit.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class BouncyCastleAgainTest {

  @Test
  public void weCanMakeCertificates() throws Exception {

    Security.addProvider(new BouncyCastleProvider());

    // make CA
    final X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
    final X500Principal dnName = new X500Principal("C=US,CN=Pivotal Root");

    final Date now = Date.from(Instant.now());
    final Date later = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));

    certGen.setSerialNumber(BigInteger.valueOf(1));
    certGen.setIssuerDN(dnName);
    certGen.setNotBefore(now);
    certGen.setNotAfter(later);
    certGen.setSubjectDN(dnName);

    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(3072);
    KeyPair caKeyPair = generator.generateKeyPair();
    certGen.setPublicKey(caKeyPair.getPublic());
    certGen.setSignatureAlgorithm("SHA1withRSA");
    X509Certificate caCert = certGen.generate(caKeyPair.getPrivate(), "BC");

    caCert.verify(caKeyPair.getPublic());

    // make intermediate
    final X509V3CertificateGenerator intermediateCertGen = new X509V3CertificateGenerator();
    final X500Principal intermediateName = new X500Principal("C=US,CN=Pivotal Admin");

    intermediateCertGen.setSerialNumber(BigInteger.valueOf(2));
    intermediateCertGen.setIssuerDN(dnName);
    intermediateCertGen.setNotBefore(now);
    intermediateCertGen.setNotAfter(later);
    intermediateCertGen.setSubjectDN(intermediateName);
    final KeyPair intermediateKeyPair = generator.generateKeyPair();
    intermediateCertGen.setPublicKey(intermediateKeyPair.getPublic());
    intermediateCertGen.setSignatureAlgorithm("SHA1withRSA");
    intermediateCertGen.addExtension(X509Extensions.BasicConstraints, true,
        new BasicConstraints(true));
    intermediateCertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
        new AuthorityKeyIdentifierStructure(caCert));

    final X509Certificate intermediateCert = intermediateCertGen.generate(caKeyPair.getPrivate(), "BC");

    intermediateCert.verify(caKeyPair.getPublic());

    // make EE
    final X509V3CertificateGenerator subjectCertGen = new X509V3CertificateGenerator();
    final X500Principal subjectName = new X500Principal("C=US,CN=Pivotal Service");

    subjectCertGen.setSerialNumber(BigInteger.valueOf(3));
    subjectCertGen.setIssuerDN(intermediateName);
    subjectCertGen.setNotBefore(now);
    subjectCertGen.setNotAfter(later);
    subjectCertGen.setSubjectDN(subjectName);
    final KeyPair subjectKeyPair = generator.generateKeyPair();
    subjectCertGen.setPublicKey(subjectKeyPair.getPublic());
    subjectCertGen.setSignatureAlgorithm("SHA1withRSA");
//    subjectCertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
//        new AuthorityKeyIdentifierStructure(intermediateCert));
//    subjectCertGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
//        new SubjectKeyIdentifierStructure(subjectKeyPair.getPublic()));

    final X509Certificate subjectCert = subjectCertGen.generate(intermediateKeyPair.getPrivate(), "BC");

    subjectCert.verify(intermediateKeyPair.getPublic());

    // validate chain
    final X509CertSelector target = new X509CertSelector();
    target.setCertificate(subjectCert);

    final TrustAnchor trustAnchor = new TrustAnchor(caCert, null);
    final PKIXBuilderParameters builderParameters = new PKIXBuilderParameters(Collections.singleton(trustAnchor), target);

//    final CertStore certStore = new JcaCertStoreBuilder()
//        .addCertificate(new X509CertificateHolder(subjectCert.getEncoded()))
//        .addCertificate(new X509CertificateHolder(intermediateCert.getEncoded()))
//        .build();
//
//    builderParameters.addCertStore(certStore);
//    builderParameters.setRevocationEnabled(false);
//
//    final CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX", "BC");
//    final CertPathBuilderResult builderResult = certPathBuilder.build(builderParameters);
//    builderResult.getCertPath();
  }
}
