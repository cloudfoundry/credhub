package org.cloudfoundry.credhub.generators;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import org.cloudfoundry.credhub.jna.libcrypto.CryptoWrapper;

@Component
public class LibcryptoRsaKeyPairGenerator {

  private final CryptoWrapper cryptoWrapper;

  @Autowired
  public LibcryptoRsaKeyPairGenerator(final CryptoWrapper cryptoWrapper) throws NoSuchAlgorithmException {
    super();
    this.cryptoWrapper = cryptoWrapper;
  }

  public synchronized KeyPair generateKeyPair(final int keyLength)
    throws InvalidKeyException, InvalidKeySpecException {
    final KeyPair[] keyPair = {null};
    cryptoWrapper.generateKeyPair(keyLength,
      byReference -> keyPair[0] = cryptoWrapper.toKeyPair(byReference));
    return keyPair[0];
  }
}
