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

    public static class UnsupportedFormatException extends Exception {
        private static final long serialVersionUID = -2669429797326574839L;
        public UnsupportedFormatException(String msg) {
            super(msg);
        }
    }

  public static PrivateKey getPrivateKey(String privateKeyPem) throws IOException, UnsupportedFormatException {
    PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem));
    Object parsed = pemParser.readObject();
    pemParser.close();
    if (!(parsed instanceof PEMKeyPair)) {
      throw new UnsupportedFormatException("format of private key is not supported.");
    }
    PEMKeyPair pemKeyPair = (PEMKeyPair) parsed;
    PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  public static PublicKey getPublicKey(String privateKeyPem) throws IOException, UnsupportedFormatException {
    PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem));
    Object parsed = pemParser.readObject();
    pemParser.close();
    if (!(parsed instanceof PEMKeyPair)) {
      throw new UnsupportedFormatException("format of private key is not supported.");
    }
    PEMKeyPair pemKeyPair = (PEMKeyPair) parsed;
    SubjectPublicKeyInfo publicKeyInfo = pemKeyPair.getPublicKeyInfo();
    return new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
  }
}
