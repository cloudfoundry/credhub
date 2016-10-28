package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import io.pivotal.security.util.CheckedConsumer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Component
public class CryptoWrapper {

  static final String ALGORITHM = "RSA";

  private final KeyFactory keyFactory;

  @Autowired
  public CryptoWrapper(BouncyCastleProvider bouncyCastleProvider) throws NoSuchAlgorithmException {
    keyFactory = KeyFactory.getInstance(ALGORITHM, bouncyCastleProvider);
  }

  public synchronized <E extends Throwable> void generateKeyPair(int keyLength, CheckedConsumer<Pointer, E> consumer) throws E {
    Pointer bne = Crypto.BN_new();
    try {
      Crypto.BN_set_word(bne, Crypto.RSA_F4);
      Pointer rsa = Crypto.RSA_new();
      int r = Crypto.RSA_generate_key_ex(rsa, keyLength, bne, null);
      if (r < 1) {
        throw new RuntimeException(String.format("RSA key generation failed: %s", getError()));
      }
      try {
        consumer.accept(rsa);
      } finally {
        Crypto.RSA_free(rsa);
      }
    } finally {
      Crypto.BN_free(bne);
    }
  }

  public synchronized KeyPair toKeyPair(Pointer rsa) throws InvalidKeySpecException {
    RSA.ByReference rsaStructure = new RSA.ByReference(rsa);
    rsaStructure.read();

    RSAPublicKeySpec publicKeySpec = getRsaPublicKeySpec(rsaStructure);
    RSAPrivateCrtKeySpec privateCrtKeySpec = getRsaPrivateCrtKeySpec(rsaStructure);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    PrivateKey privateKey = keyFactory.generatePrivate(privateCrtKeySpec);
    return new KeyPair(publicKey, privateKey);
  }

  synchronized BigInteger convert(Pointer bn) {
    Assert.notNull(bn, "bn cannot be null");
    Assert.notNull(Pointer.nativeValue(bn), "bn cannot be wrapping null");

    BIGNUM.ByReference bignum = new BIGNUM.ByReference(bn);
    bignum.read();

    int ratio = 8;
    long[] longs = bignum.d.getLongArray(0, bignum.top);
    byte[] bytes = new byte[longs.length * ratio];
    for (int i = 0; i < longs.length; i++) {
      for (int j = 0; j < ratio; j++) {
        bytes[(bytes.length - 1) - (ratio * i + j)] = (byte) (longs[i] >>> (j * ratio));
      }
    }

    return new BigInteger(bignum.neg != 0 ? -1 : 1, bytes);
  }

  synchronized String getError() {
    // use code with `openssl errstr`
    byte[] buffer = new byte[128];
    Crypto.ERR_error_string_n(Crypto.ERR_get_error(), buffer, buffer.length);
    return Native.toString(buffer);
  }

  private RSAPrivateCrtKeySpec getRsaPrivateCrtKeySpec(RSA.ByReference rsa) {
    return new RSAPrivateCrtKeySpec(
        convert(rsa.n),
        convert(rsa.e),
        convert(rsa.d),
        convert(rsa.p),
        convert(rsa.q),
        convert(rsa.dmp1),
        convert(rsa.dmq1),
        convert(rsa.iqmp)
    );
  }

  private RSAPublicKeySpec getRsaPublicKeySpec(RSA.ByReference rsa) {
    return new RSAPublicKeySpec(convert(rsa.n), convert(rsa.e));
  }
}
