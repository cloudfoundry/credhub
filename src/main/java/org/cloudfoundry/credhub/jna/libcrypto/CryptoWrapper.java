package org.cloudfoundry.credhub.jna.libcrypto;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.cloudfoundry.credhub.service.EncryptionService;
import org.cloudfoundry.credhub.util.CheckedConsumer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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

@Component
public class CryptoWrapper {
  static final String ALGORITHM = "RSA";
  // NIST SP800-90A recommends 440 bits for SHA1 seed
  private static final int NIST_SP800_90A_SEEDLENGTH = 440 / 8;

  // https://www.openssl.org/docs/manx.x.x/crypto/ERR_error_string_n.html
  // "buf must be at least 256 bytes long"
  private static final int OPENSSL_ERRBUFF_MIN_LENGTH = 256;

  private final KeyFactory keyFactory;
  private final SecureRandom secureRandom;

  @Autowired
  public CryptoWrapper(EncryptionService encryptionService) throws NoSuchAlgorithmException {
    keyFactory = KeyFactory.getInstance(ALGORITHM);
    secureRandom = encryptionService.getSecureRandom();

    initializeOpenssl();
  }

  public synchronized <E extends Throwable> void generateKeyPair(int keyLength, CheckedConsumer<Pointer, E> consumer) throws E {
    if (keyLength < 1024 || keyLength > 8096 ){
      throw new IllegalArgumentException(String.format("Invalid key length: %d", keyLength));
    }

    Pointer bne = Crypto.BN_new();
    if (bne == Pointer.NULL){
      // No need to `free` as implicit `malloc` failed
      throw new RuntimeException(String.format("RSA key generation failed: %s", getError()));
    }

    try {
      Crypto.BN_set_word(bne, Crypto.RSA_F4);
      Pointer rsa = Crypto.RSA_new();
      if (rsa == Pointer.NULL){
        // No need to `free` as implicit `malloc` failed
        throw new RuntimeException(String.format("RSA key generation failed: %s", getError()));
      }

      try {
        int r = Crypto.RSA_generate_key_ex(rsa, keyLength, bne, null);
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

  public synchronized KeyPair toKeyPair(Pointer rsa) throws InvalidKeySpecException {
    RSA.ByReference rsaStructure = new RSA.ByReference(rsa);
    rsaStructure.read();

    RSAPublicKeySpec publicKeySpec = getRsaPublicKeySpec(rsaStructure);
    RSAPrivateCrtKeySpec privateCrtKeySpec = getRsaPrivateCrtKeySpec(rsaStructure);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    PrivateKey privateKey = keyFactory.generatePrivate(privateCrtKeySpec);
    return new KeyPair(publicKey, privateKey);
  }

  synchronized BigInteger convert(Pointer bn) throws IllegalArgumentException {
    if (bn == Pointer.NULL){
      throw new IllegalArgumentException("Pointer 'bn' cannot be null");
    }

    BIGNUM.ByReference bignum = new BIGNUM.ByReference(bn);
    bignum.read();
    if (bignum.dp == null){
      throw new RuntimeException("Failed to correctly parse BigNumber");
    }

    long[] longs = bignum.dp.getLongArray(0, bignum.top);
    int ratio = 8;
    byte[] bytes = new byte[longs.length * ratio];
    for (int i = 0; i < longs.length; i++) {
      for (int j = 0; j < ratio; j++) {
        bytes[(bytes.length - 1) - (ratio * i + j)] = (byte) (longs[i] >>> (j * ratio));
      }
    }

    return new BigInteger(bignum.neg != 0 ? -1 : 1, bytes);
  }

  synchronized String getError() {
    byte[] buffer = new byte[OPENSSL_ERRBUFF_MIN_LENGTH];
    Crypto.ERR_error_string_n(Crypto.ERR_get_error(), buffer, buffer.length);
    return Native.toString(buffer);
  }

  private synchronized void initializeOpenssl() {
    byte[] seed = secureRandom.generateSeed(NIST_SP800_90A_SEEDLENGTH);
    Pointer memory = new Memory(seed.length);
    memory.write(0, seed, 0, seed.length);
    Crypto.RAND_seed(memory, seed.length);
    memory.clear(seed.length);
  }

  private RSAPrivateCrtKeySpec getRsaPrivateCrtKeySpec(RSA.ByReference rsa) {
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

  private RSAPublicKeySpec getRsaPublicKeySpec(RSA.ByReference rsa) {
    return new RSAPublicKeySpec(convert(rsa.np), convert(rsa.ep));
  }
}
