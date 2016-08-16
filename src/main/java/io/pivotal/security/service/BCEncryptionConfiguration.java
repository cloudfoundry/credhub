package io.pivotal.security.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

@Component
//@Primary
//@Profile({"dev", "unit-test"})
public class BCEncryptionConfiguration implements EncryptionConfiguration {
  private Provider provider;
  private SecureRandom secureRandom;
  private SecretKey key;

  public BCEncryptionConfiguration() {
    try {
      provider = new BouncyCastleProvider();
      Security.addProvider(provider);

      KeyStore keyStore = KeyStore.getInstance("BKS", provider);
      keyStore.load(null, null);
      secureRandom = SecureRandom.getInstance("SHA1PRNG");
      key = new SecretKeySpec(new byte[] {-102, 88, 28, 1, -97, -31, -100, 124, 59, 36, -45, -10, 70, 106, 105, -125}, "AES");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  @Override
  public SecureRandom getSecureRandom() {
    return secureRandom;
  }

  @Override
  public Key getKey() {
    return key;
  }
}
