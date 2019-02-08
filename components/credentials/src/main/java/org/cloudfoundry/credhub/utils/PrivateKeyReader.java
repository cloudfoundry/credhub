package org.cloudfoundry.credhub.utils;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

final public class PrivateKeyReader {

  private PrivateKeyReader() {
    super();
  }

  public static PrivateKey getPrivateKey(final String privateKeyPem) throws IOException, UnsupportedFormatException {
    final PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem));
    final Object parsed = pemParser.readObject();
    pemParser.close();
    if (!(parsed instanceof PEMKeyPair)) {
      throw new UnsupportedFormatException("format of private key is not supported.");
    }
    final PEMKeyPair pemKeyPair = (PEMKeyPair) parsed;
    final PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
    return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
  }

  public static PublicKey getPublicKey(final String privateKeyPem) throws IOException, UnsupportedFormatException {
    final PEMParser pemParser = new PEMParser(new StringReader(privateKeyPem));
    final Object parsed = pemParser.readObject();
    pemParser.close();
    if (!(parsed instanceof PEMKeyPair)) {
      throw new UnsupportedFormatException("format of private key is not supported.");
    }
    final PEMKeyPair pemKeyPair = (PEMKeyPair) parsed;
    final SubjectPublicKeyInfo publicKeyInfo = pemKeyPair.getPublicKeyInfo();
    return new JcaPEMKeyConverter().getPublicKey(publicKeyInfo);
  }

  public static class UnsupportedFormatException extends Exception {
    private static final long serialVersionUID = -2669429797326574839L;

    public UnsupportedFormatException(final String msg) {
      super(msg);
    }
  }
}
