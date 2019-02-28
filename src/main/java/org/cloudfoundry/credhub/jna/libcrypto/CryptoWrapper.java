package org.cloudfoundry.credhub.jna.libcrypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.cloudfoundry.credhub.service.RandomNumberGenerator;
import org.cloudfoundry.credhub.util.CheckedConsumer;

@Component
public class CryptoWrapper {
  public static final String ALGORITHM = "RSA";
  // NIST SP800-90A recommends 440 bits for SHA1 seed
  private static final int NIST_SP800_90A_SEEDLENGTH = 440 / 8;

  // https://www.openssl.org/docs/manx.x.x/crypto/ERR_error_string_n.html
  // "buf must be at least 256 bytes long"
  private static final int OPENSSL_ERRBUFF_MIN_LENGTH = 256;

  private final KeyFactory keyFactory;
  private final SecureRandom secureRandom;

  @Autowired
  public CryptoWrapper(final RandomNumberGenerator randomNumberGenerator) throws NoSuchAlgorithmException {
    super();
    keyFactory = KeyFactory.getInstance(ALGORITHM);
    secureRandom = randomNumberGenerator.getSecureRandom();

    initializeOpenssl();
  }

  public synchronized <E extends Throwable> void generateKeyPair(final int keyLength, final CheckedConsumer<Pointer, E> consumer) throws E {
    if (keyLength < 1024 || keyLength > 8096) {
      throw new IllegalArgumentException(String.format("Invalid key length: %d", keyLength));
    }

    final Pointer bne = Crypto.BN_new();
    if (bne == Pointer.NULL) {
      // No need to `free` as implicit `malloc` failed
      throw new RuntimeException(String.format("RSA key generation failed: %s", getError()));
    }

    try {
      Crypto.BN_set_word(bne, Crypto.RSA_F4);
      final Pointer rsa = Crypto.RSA_new();
      if (rsa == Pointer.NULL) {
        // No need to `free` as implicit `malloc` failed
        throw new RuntimeException(String.format("RSA key generation failed: %s", getError()));
      }

      try {
        final int r = Crypto.RSA_generate_key_ex(rsa, keyLength, bne, null);
        if (r < 1) {
          throw new RuntimeException(String.format("RSA key generation failed: %s", getError()));
        }

        consumer.accept(rsa);
      } finally {
        Crypto.RSA_free(rsa);
      }
    } finally {
      Crypto.BN_free(bne);
    }
  }

  public synchronized KeyPair toKeyPair(final Pointer rsa) throws InvalidKeySpecException {
    final RSA.ByReference rsaStructure = new RSA.ByReference(rsa);
    rsaStructure.read();

    final RSAPublicKeySpec publicKeySpec = getRsaPublicKeySpec(rsaStructure);
    final RSAPrivateCrtKeySpec privateCrtKeySpec = getRsaPrivateCrtKeySpec(rsaStructure);
    final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    final PrivateKey privateKey = keyFactory.generatePrivate(privateCrtKeySpec);
    return new KeyPair(publicKey, privateKey);
  }

  public synchronized BigInteger convert(final Pointer bn) throws IllegalArgumentException {
    if (bn == Pointer.NULL) {
      throw new IllegalArgumentException("Pointer 'bn' cannot be null");
    }

    final BIGNUM.ByReference bignum = new BIGNUM.ByReference(bn);
    bignum.read();
    if (bignum.dp == null) {
      throw new RuntimeException("Failed to correctly parse BigNumber");
    }

    final long[] longs = bignum.dp.getLongArray(0, bignum.top);
    final int ratio = 8;
    final byte[] bytes = new byte[longs.length * ratio];
    for (int i = 0; i < longs.length; i++) {
      for (int j = 0; j < ratio; j++) {
        bytes[(bytes.length - 1) - (ratio * i + j)] = (byte) (longs[i] >>> (j * ratio));
      }
    }

    return new BigInteger(bignum.neg != 0 ? -1 : 1, bytes);
  }

  public synchronized String getError() {
    final byte[] buffer = new byte[OPENSSL_ERRBUFF_MIN_LENGTH];
    Crypto.ERR_error_string_n(Crypto.ERR_get_error(), buffer, buffer.length);
    return Native.toString(buffer);
  }

  private synchronized void initializeOpenssl() {
    final byte[] seed = secureRandom.generateSeed(NIST_SP800_90A_SEEDLENGTH);
    final Pointer memory = new Memory(seed.length);
    memory.write(0, seed, 0, seed.length);
    Crypto.RAND_seed(memory, seed.length);
    memory.clear(seed.length);
  }

  private RSAPrivateCrtKeySpec getRsaPrivateCrtKeySpec(final RSA.ByReference rsa) {
    return new RSAPrivateCrtKeySpec(
      convert(rsa.np),
      convert(rsa.ep),
      convert(rsa.dp),
      convert(rsa.pp),
      convert(rsa.qp),
      convert(rsa.dmp1),
      convert(rsa.dmq1),
      convert(rsa.iqmp)
    );
  }

  private RSAPublicKeySpec getRsaPublicKeySpec(final RSA.ByReference rsa) {
    return new RSAPublicKeySpec(convert(rsa.np), convert(rsa.ep));
  }
}
