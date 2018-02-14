package org.cloudfoundry.credhub.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.credhub.entity.RsaCredentialVersionData;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

public class SecretKeyHelper {
  public static String generateSecretKey(int length) {
    Random random = new SecureRandom();

    byte[] data = new byte[length];
    random.nextBytes(data);

    return new String(Base64.encodeBase64(data));
  }
}
