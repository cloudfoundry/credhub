package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.data.CertificateAuthorityService;
import io.pivotal.security.exceptions.ParameterizedValidationException;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.util.CertificateFormatter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class BcCertificateGenerator implements
    SecretGenerator<CertificateSecretParameters, Certificate> {

  private final LibcryptoRsaKeyPairGenerator keyGenerator;
  private final SignedCertificateGenerator signedCertificateGenerator;
  private final CertificateAuthorityService certificateAuthorityService;
  private final BouncyCastleProvider provider;

  @Autowired
  public BcCertificateGenerator(
      LibcryptoRsaKeyPairGenerator keyGenerator,
      SignedCertificateGenerator signedCertificateGenerator,
      CertificateAuthorityService certificateAuthorityService,
      BouncyCastleProvider provider) {
    this.keyGenerator = keyGenerator;
    this.signedCertificateGenerator = signedCertificateGenerator;
    this.certificateAuthorityService = certificateAuthorityService;
    this.provider = provider;
  }

  @Override
  public Certificate generateSecret(CertificateSecretParameters params) {
    try {
      KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());

      if (params.isSelfSigned()) {
        X509Certificate cert = signedCertificateGenerator.getSelfSigned(keyPair, params);
        String certPem = CertificateFormatter.pemOf(cert);
        String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
        return new Certificate(null, certPem, privatePem);
      } else {
        Certificate ca = certificateAuthorityService.findMostRecent(params.getCaName());

        String caCertificate = ca.getPublicKeyCertificate();
        X500Name issuerDn = getSubjectNameOfCa(caCertificate);
        PrivateKey issuerKey = getPrivateKey(ca.getPrivateKey());

        X509Certificate cert = signedCertificateGenerator
            .getSignedByIssuer(issuerDn, issuerKey, keyPair, params);

        String certPem = CertificateFormatter.pemOf(cert);
        String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
        return new Certificate(caCertificate, certPem, privatePem);
      }
    } catch (ParameterizedValidationException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private PrivateKey getPrivateKey(String privateKey)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    PEMParser pemParser = new PEMParser(new StringReader(privateKey));
    PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  private X500Name getSubjectNameOfCa(String ca) throws IOException, CertificateException {
    X509Certificate certificate = (X509Certificate) CertificateFactory
        .getInstance("X.509", provider)
        .generateCertificate(new ByteArrayInputStream(ca.getBytes()));
    return new X500Name(certificate.getSubjectDN().getName());
  }
}
