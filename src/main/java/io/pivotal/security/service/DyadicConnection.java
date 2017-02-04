package io.pivotal.security.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

@Component
@ConditionalOnProperty(value = "encryption.provider", havingValue = "dsm", matchIfMissing = true)
class DyadicConnection  implements RemoteEncryptionConnectable, KeyGeneratingConnection {
  private Provider provider;
  private KeyStore keyStore;
  private KeyGenerator aesKeyGenerator;
  private Constructor parameterSpecConstructor;

  public DyadicConnection() throws Exception {
    provider = (Provider) Class.forName("com.dyadicsec.provider.DYCryptoProvider").newInstance();
    Security.addProvider(provider);

    parameterSpecConstructor = Class.forName("com.dyadicsec.provider.CcmParameterSpec").getConstructor(byte[].class, int.class, byte[].class);

    keyStore = KeyStore.getInstance("PKCS11", provider);
    keyStore.load(null);

    aesKeyGenerator = KeyGenerator.getInstance("AES", provider);
    aesKeyGenerator.init(128);
  }

  public Provider getProvider() {
    return provider;
  }

  public KeyGenerator getKeyGenerator() {
    return aesKeyGenerator;
  }

  public KeyStore getKeyStore() {
    return keyStore;
  }

  IvParameterSpec generateParameterSpec(byte[] nonce) {
    int numBytes = nonce != null ? nonce.length : 0;
    try {
      return (IvParameterSpec) parameterSpecConstructor.newInstance(nonce, numBytes, null);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void reconnect(Exception reasonForReconnect) {
    // does retrying make sense for Dyadic?
  }
}
