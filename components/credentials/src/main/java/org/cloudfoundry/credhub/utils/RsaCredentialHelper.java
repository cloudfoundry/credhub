package org.cloudfoundry.credhub.utils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;

public class RsaCredentialHelper {

  private static final String RSA_START = "-----BEGIN PUBLIC KEY-----\n";
  private static final String RSA_END = "\n-----END PUBLIC KEY-----";
  private static final String NEW_LINE = "\n";

  private final RsaCredentialVersionData rsaCredentialData;

  public RsaCredentialHelper(final RsaCredentialVersionData rsaCredentialData) {
    super();
    this.rsaCredentialData = rsaCredentialData;
  }

  public int getKeyLength() {
    final String publicKey = rsaCredentialData.getPublicKey();

    if (StringUtils.isEmpty(publicKey)) {
      return 0;
    }

    try {
      final String key = publicKey
        .replaceFirst(RSA_START, "")
        .replaceFirst(RSA_END, "")
        .replaceAll(NEW_LINE, "");
      final byte[] byteKey = Base64.decodeBase64(key.getBytes(StringUtil.UTF_8));
      final X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(byteKey);
      final KeyFactory kf = KeyFactory.getInstance("RSA");
      return ((RSAPublicKey) kf.generatePublic(x509publicKey)).getModulus().bitLength();
    } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }
}
