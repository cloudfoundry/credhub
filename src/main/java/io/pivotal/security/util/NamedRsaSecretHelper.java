package io.pivotal.security.util;

import io.pivotal.security.entity.NamedRsaSecretData;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

public class NamedRsaSecretHelper {

  private static final String RSA_START = "-----BEGIN PUBLIC KEY-----\n";
  private static final String RSA_END = "\n-----END PUBLIC KEY-----";
  private static final String NEW_LINE = "\n";

  private final NamedRsaSecretData namedRsaSecretData;

  public NamedRsaSecretHelper(NamedRsaSecretData namedRsaSecretData) {
    this.namedRsaSecretData = namedRsaSecretData;
  }

  public int getKeyLength() {
    String publicKey = namedRsaSecretData.getPublicKey();

    if (StringUtils.isEmpty(publicKey)) {
      return 0;
    }

    try {
      String key = publicKey
          .replaceFirst(RSA_START, "")
          .replaceFirst(RSA_END, "")
          .replaceAll(NEW_LINE, "");
      byte[] byteKey = Base64.decodeBase64(key.getBytes());
      X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(byteKey);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return ((RSAPublicKey) kf.generatePublic(x509publicKey)).getModulus().bitLength();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }
}