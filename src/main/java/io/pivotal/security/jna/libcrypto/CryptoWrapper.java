package io.pivotal.security.jna.libcrypto;

import com.sun.jna.Pointer;
import io.pivotal.security.util.CheckedConsumer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

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

  public static final String ALGORITHM = "RSA";
  private final KeyFactory keyFactory;

  @Autowired
  public CryptoWrapper(BouncyCastleProvider bouncyCastleProvider) throws NoSuchAlgorithmException {
    keyFactory = KeyFactory.getInstance(ALGORITHM, bouncyCastleProvider);
  }

  public synchronized <E extends Throwable> void generateKeyPair(int keyLength, CheckedConsumer<RSA.ByReference, E> consumer) throws E {
    BIGNUM.ByReference bne = Crypto.BN_new();
    Crypto.BN_set_word(bne, Crypto.RSA_F4);
    RSA.ByReference rsa = Crypto.RSA_new();
    Crypto.RSA_generate_key_ex(rsa, keyLength, bne, null);

    consumer.accept(rsa);

    Crypto.RSA_free(rsa);
    Crypto.BN_free(bne);
  }

  public synchronized BigInteger convert(BIGNUM.ByReference bignum) {
    Pointer pointer = Crypto.BN_bn2hex(bignum);
    BigInteger bigInteger = new BigInteger(pointer.getString(0), 16);
    Crypto.CRYPTO_free(pointer);
    return bigInteger;
  }

  public synchronized KeyPair toKeyPair(RSA.ByReference rsa) throws InvalidKeySpecException {
    RSAPublicKeySpec publicKeySpec = getRsaPublicKeySpec(rsa);
    RSAPrivateCrtKeySpec privateCrtKeySpec = getRsaPrivateCrtKeySpec(rsa);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    PrivateKey privateKey = keyFactory.generatePrivate(privateCrtKeySpec);
    return new KeyPair(publicKey, privateKey);
  }

  private RSAPrivateCrtKeySpec getRsaPrivateCrtKeySpec(RSA.ByReference rsa) {
    return new RSAPrivateCrtKeySpec(convert(rsa.n), convert(rsa.e), convert(rsa.d), convert(rsa.p), convert(rsa.q), convert(rsa.dmp1), convert(rsa.dmq1), convert(rsa.iqmp));
  }

  private RSAPublicKeySpec getRsaPublicKeySpec(RSA.ByReference rsa) {
    return new RSAPublicKeySpec(convert(rsa.n), convert(rsa.e));
  }
}
