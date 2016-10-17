package io.pivotal.security.service;

import io.pivotal.security.config.DevKeyProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateException;

import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionConfiguration implements EncryptionConfiguration {
  private SecureRandom secureRandom;
  private SecretKey key;

  @Autowired
  BouncyCastleProvider provider;

  @Autowired
  DevKeyProvider devKeyProvider;

  @PostConstruct
  public void postConstruct() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    KeyStore keyStore = KeyStore.getInstance("BKS", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("SHA1PRNG");
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
    if (key == null) {
      key = new SecretKeySpec(DatatypeConverter.parseHexBinary(devKeyProvider.getDevKey()), 0, 16, "AES");
    }
    return key;
  }
}
