package io.pivotal.security.service;

import io.pivotal.security.config.DevKeyProvider;
import io.pivotal.security.config.EncryptionKeysConfiguration;
import io.pivotal.security.constants.CipherTypes;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dev_internal")
public class BCEncryptionService extends EncryptionService {
  private SecureRandom secureRandom;
  private Key activeKey;

  private final BouncyCastleProvider provider;
  private final DevKeyProvider devKeyProvider;
  private final EncryptionKeysConfiguration encryptionKeysConfiguration;
  private List<Key> keys;

  @Autowired
  BCEncryptionService(
      BouncyCastleProvider provider,
      DevKeyProvider devKeyProvider,
      EncryptionKeysConfiguration encryptionKeysConfiguration
  ) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    this.provider = provider;
    this.devKeyProvider = devKeyProvider;
    this.encryptionKeysConfiguration = encryptionKeysConfiguration;

    KeyStore keyStore = KeyStore.getInstance("BKS", provider);
    keyStore.load(null, null);
    secureRandom = SecureRandom.getInstance("SHA1PRNG");

    initializeKeys();
  }

  private void initializeKeys() {
    keys = encryptionKeysConfiguration.getKeys().stream().map(this::createKey).collect(Collectors.toList());
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
  public Key getActiveKey() {
    return activeKey;
  }

  @Override
  public List<Key> getKeys() {
    return keys;
  }

  @Override
  public CipherWrapper getCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {
    return new CipherWrapper(Cipher.getInstance(CipherTypes.GCM.toString(), provider));
  }

  @Override
  public IvParameterSpec generateParameterSpec(byte[] nonce) {
    return new IvParameterSpec(nonce);
  }

  private Key createKey(String plaintextKey) {
    Key encryptionKey = new SecretKeySpec(DatatypeConverter.parseHexBinary(plaintextKey), 0, 16, "AES");

    // The list of keys must include the same instance as the active key in order to facilitate key comparison,
    // since we don't know that we can check key1.equals(key2) for all key types :(
    if (devKeyProvider.getDevKey().equals(plaintextKey)) {
      activeKey = encryptionKey;
    }

    return encryptionKey;
  }
}
