package io.pivotal.security.generator;

import io.pivotal.security.controller.v1.CertificateSecretParameters;
import io.pivotal.security.entity.NamedCertificateAuthority;
import io.pivotal.security.repository.CertificateAuthorityRepository;
import io.pivotal.security.util.CertificateFormatter;
import io.pivotal.security.view.CertificateAuthority;
import io.pivotal.security.view.CertificateSecret;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.validation.ValidationException;

@Component
public class BCCertificateGenerator implements SecretGenerator<CertificateSecretParameters, CertificateSecret> {

  @Autowired
  KeyPairGenerator keyGenerator;

  @Autowired
  SignedCertificateGenerator signedCertificateGenerator;

  @Autowired
  CertificateAuthorityRepository authorityRepository;

  @Override
  public CertificateSecret generateSecret(CertificateSecretParameters params) {
    keyGenerator.initialize(params.getKeyLength());
    KeyPair keyPair = keyGenerator.generateKeyPair();

    NamedCertificateAuthority ca = findCa(params.getCa());
    try {
      X500Name issuerDn = getIssuer(ca);
      PrivateKey issuerKey = getPrivateKey(ca);

      X509Certificate cert = signedCertificateGenerator.getSignedByIssuer(issuerDn, issuerKey, keyPair, params);

      String certPem = CertificateFormatter.pemOf(cert);
      String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
      return new CertificateSecret(ca.getCertificate(), certPem, privatePem);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private NamedCertificateAuthority findCa(String caName) {
    boolean hasCaName = !StringUtils.isEmpty(caName);
    String missingCaErrorMessageKey;
    if (hasCaName && !"default".equals(caName)) {
      missingCaErrorMessageKey = "error.ca_not_found_for_certificate_generation";
    } else {
      missingCaErrorMessageKey = "error.default_ca_required";
      caName = "default";
    }
    NamedCertificateAuthority ca = authorityRepository.findOneByName(caName);
    if (ca == null) {
      throw new ValidationException(missingCaErrorMessageKey);
    }
    return ca;
  }

  private PrivateKey getPrivateKey(NamedCertificateAuthority ca) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
    PEMParser pemParser = new PEMParser(new StringReader(ca.getPrivateKey()));
    PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  private X500Name getIssuer(NamedCertificateAuthority ca) throws IOException, CertificateException, NoSuchProviderException {
    X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
        .generateCertificate(new ByteArrayInputStream(ca.getCertificate().getBytes()));
    return new X500Name(certificate.getIssuerDN().getName());
  }

  public CertificateAuthority generateCertificateAuthority(CertificateSecretParameters params) throws Exception {
    keyGenerator.initialize(params.getKeyLength());
    KeyPair keyPair = keyGenerator.generateKeyPair();
    X509Certificate ca = signedCertificateGenerator.getSelfSigned(keyPair, params);
    String certPem = CertificateFormatter.pemOf(ca);
    String privatePem = CertificateFormatter.pemOf(keyPair.getPrivate());
    return new CertificateAuthority("root", certPem, privatePem);
  }
}
