package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.data.CertificateAuthorityDataService;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.secret.Certificate;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.ParameterizedValidationException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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

@Component
public class BCCertificateGenerator implements SecretGenerator<CertificateSecretParameters, Certificate> {

  @Autowired
  LibcryptoRsaKeyPairGenerator keyGenerator;

  @Autowired
  SignedCertificateGenerator signedCertificateGenerator;

  @Autowired
  CertificateAuthorityDataService certificateAuthorityDataService;

  @Autowired
  BouncyCastleProvider provider;

  @Override
  public Certificate generateSecret(CertificateSecretParameters params) {
    try {
      KeyPair keyPair = keyGenerator.generateKeyPair(params.getKeyLength());

      if (params.getSelfSign()) {
        X509Certificate cert = signedCertificateGenerator.getSelfSigned(keyPair, params);
        String certPem = CertificateFormatter.pemOf(cert);
        String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
        return new Certificate(null, certPem, privatePem);
      } else {
        NamedCertificateAuthority ca = findCa(params.getCaName());
        X500Name issuerDn = getIssuer(ca.getCertificate());
        PrivateKey issuerKey = getPrivateKey(ca);

        X509Certificate cert = signedCertificateGenerator.getSignedByIssuer(issuerDn, issuerKey, keyPair, params);

        String certPem = CertificateFormatter.pemOf(cert);
        String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
        return new Certificate(ca.getCertificate(), certPem, privatePem);
      }
    } catch (ParameterizedValidationException e) {
      throw e;
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private NamedCertificateAuthority findCa(String caName) {
    NamedCertificateAuthority mostRecentCA = certificateAuthorityDataService.findMostRecent(caName);

    if (mostRecentCA == null) {
      if ("default".equals(caName)) {
        throw new ParameterizedValidationException("error.default_ca_required");
      } else {
        throw new ParameterizedValidationException("error.ca_not_found_for_certificate_generation");
      }
    }

    return mostRecentCA;
  }

  private PrivateKey getPrivateKey(NamedCertificateAuthority ca) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    PEMParser pemParser = new PEMParser(new StringReader(ca.getPrivateKey()));
    PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  private X500Name getIssuer(String ca) throws IOException, CertificateException {
    X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", provider)
        .generateCertificate(new ByteArrayInputStream(ca.getBytes()));
    return new X500Name(certificate.getIssuerDN().getName());
  }
}
