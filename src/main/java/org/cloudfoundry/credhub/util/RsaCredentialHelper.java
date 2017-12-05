package org.cloudfoundry.credhub.util;

import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class RsaCredentialHelper {

  private static final String RSA_START = "-----BEGIN PUBLIC KEY-----\n";
  private static final String RSA_END = "\n-----END PUBLIC KEY-----";
  private static final String NEW_LINE = "\n";

  private final RsaCredentialVersionData rsaCredentialData;

  public RsaCredentialHelper(RsaCredentialVersionData rsaCredentialData) {
    this.rsaCredentialData = rsaCredentialData;
  }

  public int getKeyLength() {
    String publicKey = rsaCredentialData.getPublicKey();

    if (StringUtils.isEmpty(publicKey)) {
      return 0;
    }

    try {
      String key = publicKey
          .replaceFirst(RSA_START, "")
          .replaceFirst(RSA_END, "")
          .replaceAll(NEW_LINE, "");
      byte[] byteKey = Base64.decodeBase64(key.getBytes(StringUtil.UTF_8));
      X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(byteKey);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return ((RSAPublicKey) kf.generatePublic(x509publicKey)).getModulus().bitLength();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }
}
