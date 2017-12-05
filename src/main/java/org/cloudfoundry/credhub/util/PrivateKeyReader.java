package org.cloudfoundry.credhub.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;

public class PrivateKeyReader {

  public static PrivateKey getPrivateKey(String privateKeyPem) throws IOException {
    PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem));
    PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  public static PublicKey getPublicKey(String privateKeyPem) throws IOException {
    PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem));
    PEMKeyPair pemKeyPair = (PEMKeyPair) pemParser.readObject();
    SubjectPublicKeyInfo publicKeyInfo = pemKeyPair.getPublicKeyInfo();
    return new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
  }
}
