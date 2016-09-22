package io.pivotal.security.service;

import io.pivotal.security.config.DevKeyProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionConfiguration implements EncryptionConfiguration {
  private Provider provider;
  private SecureRandom secureRandom;
  private SecretKey key;

  @Autowired
  DevKeyProvider devKeyProvider;

  public BCEncryptionConfiguration() {
    try {
      provider = new BouncyCastleProvider();
      Security.addProvider(provider);

      KeyStore keyStore = KeyStore.getInstance("BKS", provider);
      keyStore.load(null, null);
      secureRandom = SecureRandom.getInstance("SHA1PRNG");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @PostConstruct
  public void init() {
    key = new SecretKeySpec(DatatypeConverter.parseHexBinary(devKeyProvider.getDevKey()), "AES");
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
