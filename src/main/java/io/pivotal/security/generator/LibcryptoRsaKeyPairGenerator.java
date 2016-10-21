package io.pivotal.security.generator;

import io.pivotal.security.jna.libcrypto.BIGNUM;
import io.pivotal.security.jna.libcrypto.Crypto;
import io.pivotal.security.jna.libcrypto.RSA;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

@Component
class LibcryptoRsaKeyPairGenerator {

  private final KeyFactory keyFactory;

  @Autowired
  public LibcryptoRsaKeyPairGenerator(BouncyCastleProvider bouncyCastleProvider) throws NoSuchAlgorithmException {
    keyFactory = KeyFactory.getInstance("RSA", bouncyCastleProvider);
  }

  public synchronized KeyPair generateKeyPair(int keyLength) throws InvalidKeyException, InvalidKeySpecException {
    BIGNUM.ByReference bne = Crypto.BN_new();
    Crypto.BN_set_word(bne, Crypto.RSA_F4);
    RSA.ByReference rsa = Crypto.RSA_new();
    Crypto.RSA_generate_key_ex(rsa, keyLength, bne, null);

    KeyPair keyPair = toKeyPair(rsa);

    Crypto.RSA_free(rsa);
    Crypto.BN_free(bne);

    return keyPair;
  }

  private KeyPair toKeyPair(RSA.ByReference rsa) throws InvalidKeySpecException {
    KeyPair keyPair;RSAPublicKeySpec publicKeySpec = getRsaPublicKeySpec(rsa);
    RSAPrivateCrtKeySpec privateCrtKeySpec = getRsaPrivateCrtKeySpec(rsa);
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
    PrivateKey privateKey = keyFactory.generatePrivate(privateCrtKeySpec);
    keyPair = new KeyPair(publicKey, privateKey);
    return keyPair;
  }

  private RSAPrivateCrtKeySpec getRsaPrivateCrtKeySpec(RSA.ByReference rsa) {
    return new RSAPrivateCrtKeySpec(convert(rsa.n), convert(rsa.e), convert(rsa.d), convert(rsa.p), convert(rsa.q), convert(rsa.dmp1), convert(rsa.dmq1), convert(rsa.iqmp));
  }

  private RSAPublicKeySpec getRsaPublicKeySpec(RSA.ByReference rsa) {
    return new RSAPublicKeySpec(convert(rsa.n), convert(rsa.e));
  }

  private BigInteger convert(BIGNUM.ByReference bignum) {
    return new BigInteger(Crypto.BN_bn2hex(bignum), 16);
  }
}
