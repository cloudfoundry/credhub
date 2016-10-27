package io.pivotal.security.generator;

import io.pivotal.security.jna.libcrypto.CryptoWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

@Component
class LibcryptoRsaKeyPairGenerator {

  private final CryptoWrapper cryptoWrapper;

  @Autowired
  public LibcryptoRsaKeyPairGenerator(CryptoWrapper cryptoWrapper) throws NoSuchAlgorithmException {
    this.cryptoWrapper = cryptoWrapper;
  }

  public synchronized KeyPair generateKeyPair(int keyLength) throws InvalidKeyException, InvalidKeySpecException {
    return cryptoWrapper.toKeyPair(cryptoWrapper.generateKeyPair(keyLength));
  }
}
